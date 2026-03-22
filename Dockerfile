FROM python:3.12-slim
WORKDIR /app
COPY server.py index.html login.html ./
ENV PORT=8080
EXPOSE 8080
CMD ["python3", "server.py"]
