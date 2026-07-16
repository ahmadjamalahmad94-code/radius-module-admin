# HobeHub License Panel — production image
# البناء: docker build -t hobehub-panel .
# السياق مبنيّ على allowlist في .dockerignore (كل شيء مستبعَد إلا المذكور) —
# نفس درس صورة الراديوس: بدون allowlist تتضخم الصورة بمخلفات المستودع.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # fail-closed: أي تشغيل حاوية = إنتاج ما لم يُصرَّح غير ذلك
    LICENSE_PANEL_ENV=production

WORKDIR /srv/panel

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-production.txt ./
RUN pip install -r requirements-production.txt

COPY app ./app
COPY fleet ./fleet
COPY migrations ./migrations
COPY wsgi.py run.py ./

RUN useradd --system --home /srv/panel panel \
 && mkdir -p /var/lib/hobehub/instance \
 && chown -R panel:panel /srv/panel /var/lib/hobehub
USER panel

# قاعدة البيانات والملفات المتولدة تعيش خارج الصورة (volume)
ENV LICENSE_PANEL_INSTANCE_DIR=/var/lib/hobehub/instance
VOLUME ["/var/lib/hobehub/instance"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsS http://127.0.0.1:8000/login >/dev/null || exit 1

# ملاحظة: عامل واحد الآن (خيوط الخلفية غير آمنة للتعدد — لا leader election بعد).
# عند نقل المهام الدورية لعملية مستقلة يمكن رفع --workers.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "120", "wsgi:app"]
