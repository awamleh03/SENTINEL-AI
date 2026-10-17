# استخدام صورة بايثون الرسمية
FROM python:3.10-slim

# تثبيت متطلبات النظام الأساسية (مثل أدوات معالجة الصور إذا لزم الأمر لـ CamGuard)
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# تحديد مجلد العمل داخل الحاوية
WORKDIR /app


# نسخ ملف المتطلبات من داخل مجلد backend وتثبيتها
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع
COPY . .

# فتح المنفذ الذي يعمل عليه تطبيق FastAPI
EXPOSE 8000

# أمر تشغيل التطبيق
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]