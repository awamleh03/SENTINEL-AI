import os
import sys
import io
import logging
import datetime
import base64
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

try:
    import cv2
    import numpy as np
    OPENCV_AVAILABLE = True
except ImportError:
    cv2 = None
    np = None
    OPENCV_AVAILABLE = False

try:
    from ultralytics import YOLO
    YOLO_AVAILABLE = True
except ImportError:
    YOLO = None
    YOLO_AVAILABLE = False

from modules.database import save_scan_record, save_alert_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

camguard_bp = Blueprint('camguard', __name__, url_prefix='/api/camguard')

_PREV_FRAME = {}
_YOLO_MODEL_INSTANCE = None


def _load_yolo_model(weights='yolov8n.pt'):
    """Loads the YOLOv8 model using ultralytics if available."""
    global _YOLO_MODEL_INSTANCE
    if not YOLO_AVAILABLE:
        return None
    if _YOLO_MODEL_INSTANCE is not None:
        return _YOLO_MODEL_INSTANCE
    try:
        model_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), weights)
        if os.path.exists(model_path):
            _YOLO_MODEL_INSTANCE = YOLO(model_path)
            logger.info(f"YOLO model loaded from {model_path}")
        else:
            try:
                _YOLO_MODEL_INSTANCE = YOLO(weights)
                logger.info(f"YOLO model loaded (default weights '{weights}')")
            except Exception as e:
                logger.warning(f"Could not load YOLO model with '{weights}': {str(e)}")
                _YOLO_MODEL_INSTANCE = None
    except Exception as e:
        logger.warning(f"YOLO model loading failed: {str(e)}")
        _YOLO_MODEL_INSTANCE = None
    return _YOLO_MODEL_INSTANCE


def _decode_image_from_request():
    """Accept image as multipart file, base64 in JSON, or raw bytes. Returns numpy BGR frame or None."""
    if not OPENCV_AVAILABLE or np is None:
        return None, 'OpenCV/numpy not available'
    file = request.files.get('frame') or request.files.get('image')
    if file:
        raw = file.read()
    else:
        data = request.get_json(silent=True)
        if data and ('frame' in data or 'image' in data or 'base64' in data):
            b64 = data.get('frame') or data.get('image') or data.get('base64')
            if isinstance(b64, str):
                b64 = b64.split(',')[-1] if ',' in b64 else b64
                try:
                    raw = base64.b64decode(b64, validate=False)
                except Exception as e:
                    return None, f'Invalid base64: {str(e)[:100]}'
            else:
                return None, '"frame"/"image"/"base64" must be a string'
        else:
            raw_data = request.get_data(cache=False)
            raw = raw_data if raw_data and len(raw_data) > 100 else None
            if not raw:
                return None, ('No image provided. Send multipart file "frame", '
                              'JSON with base64 "frame" field, or raw image bytes.')
    if not raw or len(raw) < 32:
        return None, 'Empty or too-small image payload'
    try:
        arr = np.frombuffer(raw, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None or img.size == 0:
            return None, 'Failed to decode image (format may be unsupported or corrupted)'
        return img, None
    except Exception as e:
        return None, f'Image decode error: {str(e)[:200]}'


def _detect_motion(current_frame, camera_id='default', sensitivity=25, min_area=500, history_weight=0.7):
    """Fallback basic motion detection using background subtraction."""
    if not OPENCV_AVAILABLE or np is None:
        return False, 0, 0, [], 0.0
    prev = _PREV_FRAME.get(camera_id)
    h, w = current_frame.shape[:2]
    try:
        gray = cv2.cvtColor(current_frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (21, 21), 0)
    except Exception:
        return False, 0, 0, [], 0.0

    if prev is None:
        _PREV_FRAME[camera_id] = gray
        return False, 0, 0, [], 0.0

    blended = cv2.addWeighted(prev, 1 - history_weight, gray, history_weight, 0)
    delta = cv2.absdiff(blended, gray)
    _PREV_FRAME[camera_id] = blended

    _, thresh = cv2.threshold(delta, sensitivity, 255, cv2.THRESH_BINARY)
    thresh = cv2.dilate(thresh, None, iterations=2)
    try:
        contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    except Exception:
        contours = []

    boxes = []
    max_area = 0
    total_area = 0
    for c in contours:
        area = cv2.contourArea(c)
        if area < min_area:
            continue
        max_area = max(max_area, area)
        total_area += area
        x, y, bw, bh = cv2.boundingRect(c)
        boxes.append({
            'x': int(x), 'y': int(y), 'width': int(bw), 'height': int(bh),
            'area': int(area)
        })
    frame_area = h * w
    motion_score = min(100.0, round((total_area / max(1, frame_area)) * 400, 2))
    motion_detected = len(boxes) > 0
    return motion_detected, len(boxes), int(max_area), boxes, motion_score


def _run_yolo_detection(frame, model, conf_threshold=0.45):
    """YOLO object detection — runs object detection using YOLOv8."""
    if model is None or frame is None:
        return [], 0
    try:
        results = model(frame, conf=conf_threshold, verbose=False)
        detections = []
        max_conf = 0
        for r in results:
            if hasattr(r, 'boxes') and r.boxes is not None:
                for box in r.boxes:
                    try:
                        xyxy = box.xyxy[0].tolist()
                        conf = float(box.conf[0])
                        cls_id = int(box.cls[0])
                        cls_name = model.names.get(cls_id, str(cls_id)) if hasattr(model, 'names') else str(cls_id)
                        max_conf = max(max_conf, conf)
                        detections.append({
                            'class': cls_name,
                            'class_id': cls_id,
                            'confidence': round(conf, 4),
                            'bbox': {
                                'x': int(xyxy[0]), 'y': int(xyxy[1]),
                                'width': int(xyxy[2] - xyxy[0]),
                                'height': int(xyxy[3] - xyxy[1])
                            }
                        })
                    except Exception:
                        continue
        return detections, max_conf
    except Exception as e:
        logger.error(f"YOLO detection error: {str(e)}")
        return [], 0


def _classify_scene(frame_shape, motion_score, yolo_detections):
    people = sum(1 for d in yolo_detections if d.get('class') in ('person', 'Person'))
    vehicles = sum(1 for d in yolo_detections if d.get('class') in ('car', 'truck', 'bus', 'motorcycle', 'bicycle'))
    weapons = sum(1 for d in yolo_detections if d.get('class', '').lower() in ('knife', 'scissors', 'baseball bat'))
    risk = 0
    tags = []
    if people == 0 and motion_score > 30:
        risk += 15
        tags.append('unattended_motion')
    if people >= 3:
        risk += 15
        tags.append('crowd_detected')
    if weapons > 0:
        risk += 70
        tags.append('weapon_detected')
    if vehicles > 3 and motion_score > 50:
        risk += 25
        tags.append('heavy_vehicle_activity')
    if motion_score >= 80:
        risk += 25
        tags.append('high_motion')
    elif motion_score >= 50:
        risk += 10
        tags.append('moderate_motion')
    if not tags:
        tags.append('normal')
        risk += 0
    risk = min(round(risk, 2), 100)
    level = 'critical' if risk >= 70 else 'high' if risk >= 40 else 'medium' if risk >= 15 else 'low'
    return {
        'people_count': people,
        'vehicle_count': vehicles,
        'weapon_count': weapons,
        'risk_score': risk,
        'risk_level': level,
        'tags': tags
    }


@camguard_bp.route('/analyze', methods=['POST'])
def analyze():
    try:
        camera_id = request.form.get('camera_id', 'default') if request.files else \
            (request.get_json(silent=True) or {}).get('camera_id', 'default')
        sensitivity = int((request.form.get('sensitivity') if request.files else
                          (request.get_json(silent=True) or {}).get('sensitivity')) or 25)
        min_area = int((request.form.get('min_area') if request.files else
                       (request.get_json(silent=True) or {}).get('min_area')) or 500)
        run_yolo = str((request.form.get('yolo') if request.files else
                        (request.get_json(silent=True) or {}).get('yolo', 'true'))).lower() \
                    not in ('0', 'false', 'no', 'off')

        frame, error = _decode_image_from_request()
        if error:
            return jsonify({'error': error}), 400

        h, w = frame.shape[:2]
        
        # Load and run YOLOv8 model for active AI object detection
        yolo_model = _load_yolo_model('yolov8n.pt') if run_yolo else None
        yolo_detections, yolo_max_conf = _run_yolo_detection(frame, yolo_model) if run_yolo else ([], 0)

        # Retain motion metrics as supplement if needed
        motion_detected, contour_count, max_area, boxes, motion_score = _detect_motion(
            frame, camera_id=camera_id, sensitivity=sensitivity, min_area=min_area
        )

        scene = _classify_scene((h, w), motion_score, yolo_detections)

        # Clearly indicate if no important objects are detected
        no_objects_detected = len(yolo_detections) == 0

        result = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'camera_id': camera_id,
            'frame_info': {
                'width': w,
                'height': h,
                'channels': frame.shape[2] if len(frame.shape) == 3 else 1
            },
            'detected_objects': yolo_detections,
            'no_objects_detected': no_objects_detected,
            'detection_status_message': 'No important objects detected in the current frame.' if no_objects_detected else f'Successfully detected {len(yolo_detections)} object(s).',
            'motion': {
                'detected': motion_detected,
                'contour_count': contour_count,
                'max_contour_area': max_area,
                'motion_score': motion_score,
                'bboxes': boxes[:20]
            },
            'yolo': {
                'status': {
                    'enabled': run_yolo,
                    'loaded': yolo_model is not None,
                    'max_confidence': round(yolo_max_conf, 4)
                },
                'detections': yolo_detections,
                'detection_count': len(yolo_detections)
            },
            'scene': scene,
            'risk_score': scene['risk_score'],
            'risk_level': scene['risk_level']
        }

        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None

        scan_id = save_scan_record(
            current_app._get_current_object(),
            user_id=user_id,
            module='camguard',
            target=f'camera:{camera_id}',
            risk_score=result['risk_score'],
            details={
                'scene': scene,
                'motion_score': motion_score,
                'yolo_count': len(yolo_detections)
            },
            raw_input_size=h * w * 3
        )
        result['scan_id'] = scan_id

        if result['risk_score'] >= 40:
            save_alert_record(
                current_app._get_current_object(),
                user_id=user_id,
                source='camguard',
                severity='high' if result['risk_score'] >= 70 else 'medium',
                title=f'CamGuard alert: {", ".join(scene["tags"])}',
                message=(f'Camera {camera_id}: risk score {result["risk_score"]}. '
                         f'Objects detected: {len(yolo_detections)}.'),
                alert_metadata={'scan_id': scan_id, 'tags': scene['tags'], 'camera_id': camera_id}
            )

        logger.info(f"CamGuard analyze: camera={camera_id} risk={result['risk_score']} yolo_objects={len(yolo_detections)}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"CamGuard analyze error: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)[:200]}'}), 500


@camguard_bp.route('/health', methods=['GET'])
def health():
    return jsonify({
        'opencv_available': OPENCV_AVAILABLE,
        'yolo_available': YOLO_AVAILABLE,
        'yolo_model_loaded': _YOLO_MODEL_INSTANCE is not None,
        'cached_frames': list(_PREV_FRAME.keys()),
        'yolo_integration_status': 'Active YOLOv8 object detection enabled.'
    }), 200


@camguard_bp.route('/reset', methods=['POST'])
def reset():
    global _PREV_FRAME
    _PREV_FRAME = {}
    return jsonify({'message': 'CamGuard cache reset. Motion and baseline states cleared.'}), 200
