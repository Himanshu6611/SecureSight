'''
utils/image_analysis.py
-----------------------
Forensic & AI detection pipeline for digital images.
'''
import os
import io
import numpy as np

try:
    from scipy import ndimage
    from PIL import Image, ImageChops, ImageEnhance, ExifTags
    IMAGE_LIBS_AVAILABLE = True
except ImportError:
    IMAGE_LIBS_AVAILABLE = False
    Image = None
    ndimage = None
    ImageChops = None
    ImageEnhance = None
    ExifTags = None

try:
    import torch
    from transformers import pipeline
    ML_AVAILABLE = True
except Exception as e:
    ML_AVAILABLE = False

if IMAGE_LIBS_AVAILABLE and Image:
    Image.MAX_IMAGE_PIXELS = 16777216

class AIDetector:
    def __init__(self):
        self.model_name = 'openai/clip-vit-base-patch32'
        self.classifier = None
        self._load_failed = False

    def load_model(self):
        if not ML_AVAILABLE or self._load_failed:
            return
        if self.classifier is None:
            try:
                self.classifier = pipeline('zero-shot-image-classification', model=self.model_name)
            except Exception as e:
                print(f"Error loading model: {e}")
                self._load_failed = True

    def perform_ela(self, image):
        '''Error Level Analysis (ELA) to detect manipulation or GAN artifacts.'''
        if not IMAGE_LIBS_AVAILABLE or not Image:
            return 0.0
        try:
            rgb_img = image.convert('RGB')
            buf = io.BytesIO()
            rgb_img.save(buf, format='JPEG', quality=90)
            buf.seek(0)
            ela_img = Image.open(buf)
            diff = ImageChops.difference(rgb_img, ela_img)
            extrema = diff.getextrema()
            max_diff = max([ex[1] for ex in extrema]) if extrema else 1.0
            if max_diff == 0:
                max_diff = 1.0
            scale = 255.0 / max_diff
            enhanced = ImageEnhance.Brightness(diff).enhance(scale * 15.0)
            ela_arr = np.array(enhanced)
            mean_diff = np.mean(ela_arr) / 255.0
            return min(1.0, max(0.0, float(mean_diff)))
        except Exception as e:
            print(f"ELA error: {e}")
            return 0.0

    def check_metadata(self, image):
        '''Extracts EXIF and checks for known AI generation tool tags.'''
        if not IMAGE_LIBS_AVAILABLE or not ExifTags:
            return 0.0, []
        try:
            exif = image.getexif()
            if not exif:
                return 0.3, ['missing_metadata']
            metadata_flags = []
            software_tag = ExifTags.TAGS.get('Software', 'Software')
            software = str(exif.get(software_tag, '')).lower()
            ai_tools = ['midjourney', 'dall-e', 'stable diffusion', 'comfyui', 'automatic1111']
            if any(tool in software for tool in ai_tools):
                metadata_flags.append('metadata_anomaly')
                return 1.0, metadata_flags
            return 0.0, metadata_flags
        except Exception:
            return 0.0, []

    def perform_fft_analysis(self, image):
        '''Fast Fourier Transform (FFT) analysis to detect grid-like artifacts common in GANs.'''
        if not IMAGE_LIBS_AVAILABLE:
            return 0.0
        try:
            gray = image.convert('L')
            arr = np.array(gray)
            f = np.fft.fft2(arr)
            fshift = np.fft.fftshift(f)
            magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1e-8)
            h, w = arr.shape
            cx, cy = w // 2, h // 2
            r = min(h, w) // 4
            y, x = np.ogrid[-cy:h-cy, -cx:w-cx]
            mask = x * x + y * y >= r * r
            high_freq_energy = np.mean(magnitude_spectrum[mask])
            total_energy = np.mean(magnitude_spectrum)
            if total_energy == 0:
                return 0.0
            ratio = high_freq_energy / total_energy
            risk = min(1.0, max(0.0, (ratio - 0.85) * 5.0))
            return float(risk)
        except Exception as e:
            print(f"FFT error: {e}")
            return 0.0

    def perform_noise_analysis(self, image):
        '''Noise uniformity check: AI images tend to have unnaturally uniform noise.'''
        if not IMAGE_LIBS_AVAILABLE or not ndimage:
            return 0.0
        try:
            gray = np.array(image.convert('L'), dtype=np.float32)
            laplacian = ndimage.laplace(gray)
            h, w = gray.shape
            block_size = 32
            variances = []
            for y in range(0, h - block_size, block_size):
                for x in range(0, w - block_size, block_size):
                    block = laplacian[y:y+block_size, x:x+block_size]
                    variances.append(np.var(block))
            if not variances:
                return 0.0
            mean_var = np.mean(variances)
            std_var = np.std(variances)
            cv = std_var / (mean_var + 1e-8)
            risk = max(0.0, 1.0 - cv / 0.8)
            return min(1.0, float(risk))
        except Exception as e:
            print(f"Noise analysis error: {e}")
            return 0.0

    def analyze(self, image):
        '''Main analysis pipeline combining metadata, ELA forensics, and Deep Learning (CLIP).'''
        ela_score = self.perform_ela(image)
        metadata_risk, metadata_flags = self.check_metadata(image)
        fft_score = self.perform_fft_analysis(image)
        noise_score = self.perform_noise_analysis(image)
        ml_risk = 0.5
        ml_signals = []
        
        self.load_model()
        if self.classifier:
            try:
                candidate_labels = [
                    'real authentic photo',
                    'AI generated image',
                    'deepfake image',
                    'digitally manipulated image'
                ]
                results = self.classifier(image, candidate_labels=candidate_labels)
                ai_prob = 0.0
                for res in results:
                    if res['label'] in ('AI generated image', 'deepfake image', 'digitally manipulated image'):
                        ai_prob += res['score']
                ml_risk = ai_prob
                if ai_prob > 0.6:
                    ml_signals.append('gan_artifacts')
            except Exception as e:
                print(f"Inference error: {e}")
                ml_signals.append('inference_failed')

        freq_noise_score = (fft_score + noise_score) / 2.0
        weighted_score = ml_risk * 0.35 + ela_score * 0.25 + freq_noise_score * 0.25 + metadata_risk * 0.15
        risk_score = min(100, int(weighted_score * 100))
        
        signals_array = np.array([ml_risk, ela_score, freq_noise_score, metadata_risk])
        signal_variance = float(np.var(signals_array))
        confidence = max(0.4, 1.0 - signal_variance * 2.0)
        
        signals = ml_signals + metadata_flags
        if ela_score > 0.5:
            signals.append('compression_inconsistency')
        if fft_score > 0.6:
            signals.append('frequency_anomaly')
        if noise_score > 0.6:
            signals.append('unnatural_noise_uniformity')
            
        return {
            'risk_score': risk_score,
            'confidence': round(confidence, 2),
            'is_ai_generated': risk_score >= 60,
            'signals': list(set(signals)),
            'ela_score': round(ela_score, 2),
            'ml_risk': round(ml_risk, 2),
            'fft_score': round(fft_score, 2),
            'noise_score': round(noise_score, 2)
        }

detector = AIDetector()

def analyze_image(file_storage):
    if not IMAGE_LIBS_AVAILABLE or not Image:
        raise ValueError('Image analysis dependencies (Pillow / SciPy) are not available.')
    file_bytes = file_storage.read()
    file_storage.seek(0)
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        image = Image.open(io.BytesIO(file_bytes))
        if image.width > 4096 or image.height > 4096:
            raise ValueError('Image dimensions exceed the 4096x4096 limit.')
        return detector.analyze(image)
    except ValueError as ve:
        raise ve
    except Exception as e:
        raise ValueError(f'Invalid or corrupted image format: {e}')
