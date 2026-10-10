"""Train/evaluate the compact experimental AI-origin image classifier.

Training data must be obtained under the recorded Apache-2.0 dataset license.
The script intentionally splits adjacent authentic/synthetic image pairs as a
group to prevent paired-content leakage across train and validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch
from PIL import Image, ImageOps
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             confusion_matrix, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from torch import nn
from torch.utils.data import DataLoader, Dataset


class CompactCNN(nn.Module):
    def __init__(self):
        super().__init__()
        layers = []
        channels = (3, 16, 24, 32, 48, 64)
        for source, target in zip(channels, channels[1:]):
            layers.extend((nn.Conv2d(source, target, 3, stride=2, padding=1, bias=False),
                           nn.BatchNorm2d(target), nn.ReLU(inplace=True)))
        self.features = nn.Sequential(*layers)
        self.head = nn.Sequential(nn.AdaptiveAvgPool2d(1), nn.Flatten(), nn.Linear(64, 1))

    def forward(self, x):
        return self.head(self.features(x)).squeeze(1)


class Images(Dataset):
    def __init__(self, blobs, labels, augment=False, jpeg_quality=None):
        self.blobs, self.labels, self.augment = blobs, labels, augment
        self.jpeg_quality = jpeg_quality

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        with Image.open(__import__('io').BytesIO(self.blobs[idx])) as image:
            image = ImageOps.exif_transpose(image).convert('RGB')
            if self.jpeg_quality is not None:
                buffer = __import__('io').BytesIO()
                image.save(buffer, format='JPEG', quality=self.jpeg_quality)
                buffer.seek(0)
                image = Image.open(buffer).convert('RGB')
            # Use the same deterministic transform at train and inference time.
            image = ImageOps.fit(image, (96, 96), method=Image.Resampling.BICUBIC,
                                 centering=(0.5, 0.5))
            if self.augment and torch.rand(()) < 0.5:
                image = ImageOps.mirror(image)
            array = np.asarray(image, dtype=np.float32).copy() / 255.0
        tensor = torch.from_numpy(array).permute(2, 0, 1)
        if self.augment:
            # Mild, label-preserving perturbations to reduce exact-JPEG shortcuts.
            tensor = (tensor * float(torch.empty(()).uniform_(0.92, 1.08))).clamp_(0, 1)
        return tensor, torch.tensor(float(self.labels[idx]))


def read_parquet(path: Path, max_rows: int | None):
    table = pq.read_table(path, columns=['image', 'label'])
    if max_rows:
        table = table.slice(0, max_rows)
    images = table.column('image').combine_chunks().field('bytes').to_pylist()
    labels = np.asarray(table.column('label').to_pylist(), dtype=np.int64)
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError('Expected binary labels 0=authentic, 1=AI-generated.')
    return images, labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parquet', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=Path('models/image_origin'))
    parser.add_argument('--max-rows', type=int, default=7995)
    parser.add_argument('--epochs', type=int, default=5)
    args = parser.parse_args()
    torch.manual_seed(20261010)
    np.random.seed(20261010)
    torch.set_num_threads(4)
    images, labels = read_parquet(args.parquet, args.max_rows)
    # Source rows are ordered as real/AI pairs. Group each adjacent pair before
    # splitting so their shared subject/prompt cannot leak into validation.
    groups = np.arange(len(labels)) // 2
    train_valid_split = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=20261010)
    train_valid_idx, test_idx = next(train_valid_split.split(np.zeros(len(labels)), labels, groups))
    train_valid_groups = groups[train_valid_idx]
    train_split = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=20261011)
    train_rel, valid_rel = next(train_split.split(np.zeros(len(train_valid_idx)), labels[train_valid_idx], train_valid_groups))
    train_idx, valid_idx = train_valid_idx[train_rel], train_valid_idx[valid_rel]
    model = CompactCNN()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.0005)
    loss_fn = nn.BCEWithLogitsLoss()
    train_loader = DataLoader(Images([images[i] for i in train_idx], labels[train_idx], True),
                              batch_size=64, shuffle=True, num_workers=0)
    valid_loader = DataLoader(Images([images[i] for i in valid_idx], labels[valid_idx]),
                              batch_size=64, shuffle=False, num_workers=0)
    for epoch in range(args.epochs):
        model.train()
        losses = []
        for x, y in train_loader:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(x), y)
            loss.backward()
            optimizer.step()
            losses.append(loss.item())
        print(f'epoch={epoch + 1} train_loss={np.mean(losses):.4f}', flush=True)

    model.eval()
    logits, truth = [], []
    with torch.inference_mode():
        for x, y in valid_loader:
            logits.extend(model(x).numpy().tolist())
            truth.extend(y.numpy().astype(int).tolist())
    valid_scores = 1 / (1 + np.exp(-np.asarray(logits)))
    valid_truth = np.asarray(truth)
    # Select an operating point on validation only, targeting <=5% FPR.
    negative_scores = valid_scores[valid_truth == 0]
    threshold = float(np.quantile(negative_scores, 0.95, method='higher'))

    def predict(blob_subset, label_subset, jpeg_quality=None):
        loader = DataLoader(Images(blob_subset, label_subset, jpeg_quality=jpeg_quality),
                            batch_size=64, shuffle=False, num_workers=0)
        raw_logits, actual = [], []
        with torch.inference_mode():
            for x, y in loader:
                raw_logits.extend(model(x).numpy().tolist())
                actual.extend(y.numpy().astype(int).tolist())
        return np.asarray(actual), 1 / (1 + np.exp(-np.asarray(raw_logits)))

    def summarize(actual, values, selected_threshold):
        predicted = (values >= selected_threshold).astype(int)
        matrix = confusion_matrix(actual, predicted, labels=[0, 1]).tolist()
        tn, fp, fn, tp = np.asarray(matrix).ravel().tolist()
        return {'accuracy': float(accuracy_score(actual, predicted)),
                'balanced_accuracy': float(balanced_accuracy_score(actual, predicted)),
                'roc_auc': float(roc_auc_score(actual, values)),
                'false_positive_rate': fp / (fp + tn) if fp + tn else None,
                'false_negative_rate': fn / (fn + tp) if fn + tp else None,
                'confusion_matrix_labels_0_authentic_1_ai': matrix}

    test_truth = np.asarray([labels[i] for i in test_idx])
    test_blobs = [images[i] for i in test_idx]
    test_truth, test_scores = predict(test_blobs, test_truth)
    _, recompressed_scores = predict(test_blobs, test_truth, jpeg_quality=82)
    metrics = {
        'dataset': {
            'name': 'AI vs Human Generated Dataset',
            'source': 'Kaggle/alessandrasala79; mirrored on Hugging Face by Ransaka',
            'license': 'Apache-2.0 (provider-declared; preserve upstream attribution)',
            'license_source': 'https://www.innovatiana.com/en/datasets/ai-vs-human-generated-dataset',
            'upstream': 'https://www.kaggle.com/datasets/alessandrasala79/ai-vs-human-generated-dataset',
            'labels': {'0': 'authentic Shutterstock image', '1': 'AI-generated counterpart'},
            'pair_grouping': 'adjacent authentic/synthetic equivalents kept in a single split',
            'used_shard': args.parquet.name,
            'source_shard_sha256': hashlib.sha256(args.parquet.read_bytes()).hexdigest(),
        },
        'architecture': 'Compact 5-stage CNN, 96x96 RGB, trained from scratch',
        'validation_split': 'pair-grouped validation split from licensed dataset train shard 0',
        'test_split': 'separate pair-grouped holdout; untouched during model fitting and threshold selection',
        'train_examples': len(train_idx), 'validation_examples': len(valid_idx), 'test_examples': len(test_idx),
        'pair_groups_disjoint': not (bool(set(groups[train_idx]) & set(groups[valid_idx])) or
                                     bool(set(groups[train_idx]) & set(groups[test_idx])) or
                                     bool(set(groups[valid_idx]) & set(groups[test_idx]))),
        'validation_target_fpr': 0.05,
        'validation_threshold': threshold,
        'test_at_selected_threshold': summarize(test_truth, test_scores, threshold),
        'test_at_default_0_5': summarize(test_truth, test_scores, 0.5),
        'jpeg_reencoded_test_at_selected_threshold_quality_82': summarize(test_truth, recompressed_scores, threshold),
        'score_is_calibrated_probability': False,
        'limitation': 'Single source dataset and one source shard; no independent generator, social-media, deepfake, or real-world test.'
    }
    args.output.mkdir(parents=True, exist_ok=True)
    onnx_path = args.output / 'image_origin_cnn.onnx'
    torch.onnx.export(model, torch.zeros(1, 3, 96, 96), str(onnx_path),
                      input_names=['image'], output_names=['logit'],
                      opset_version=17, dynamo=False)
    metrics['model_sha256'] = hashlib.sha256(onnx_path.read_bytes()).hexdigest()
    metrics['decision_threshold'] = threshold
    (args.output / 'evaluation.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metrics, indent=2), flush=True)


if __name__ == '__main__':
    main()
