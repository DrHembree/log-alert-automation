FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY data ./data
RUN mkdir -p /app/reports
ENV LOG_PATH=/app/data/sample_logs/syslog_sample.log
ENV OUT_DIR=/app/reports
ENV RULES="failed_logins errors sudo_failures web_unauthorized"
ENV FORMATS="json"
ENV WINDOW=300
ENV THRESHOLD=3
CMD python src/log_analyzer.py --log ${LOG_PATH} --out ${OUT_DIR} --format ${FORMATS} --rules ${RULES} --window ${WINDOW} --threshold ${THRESHOLD}