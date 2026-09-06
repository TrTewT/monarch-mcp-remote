# Le serveur amont exige Python >= 3.12, < 3.14.
FROM python:3.12-slim

# git est necessaire pour installer le serveur amont depuis GitHub ; on le
# retire ensuite pour ne pas trainer d'outillage inutile dans l'image finale.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y git && apt-get autoremove -y

COPY remote_server.py .

# Utilisateur non root : la session Monarch est ecrite dans son HOME, en 0600.
RUN useradd --create-home --uid 10001 monarch
USER monarch
ENV HOME=/home/monarch

# Render, Fly et Railway injectent PORT ; 8000 sert de valeur de repli locale.
ENV PORT=8000
EXPOSE 8000

CMD ["python", "remote_server.py"]
