# 환경 설정
## 기초 라이브러리 설치
main.py를 실행시키기 위해서는 다음과 같은 requirements들을 만족해야 합니다.
```bash
Flask==2.2.2
Flask-SQLAlchemy==2.5.1
Flask-SocketIO==5.3.0
Flask-Login==0.6.2
Werkzeug==2.2.2
```
이들은 모두 requirements.txt에 저장되어 있으니, 터미널에서 다음 명령어를 실행시켜 주시면 됩니다.
```bash
pip install -r requirements.txt
```
## ngrok 설치
서버가 원격으로 돌아갈 수 있도록, ngrok를 사용해야 합니다.
터미널에서 다음과 같은 명령어를 입력합니다.
```bash
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  | sudo tee /etc/apt/sources.list.d/ngrok.list \
  && sudo apt update \
  && sudo apt install ngrok
```
그리고, ngrok에 로그인 한 뒤에 token을 받아 다음과 같이 입력하고, 포트 번호인 5000에 맞춰 다음과 같이 입력해줍니다.
```bash
ngrok config add-authtoken <token>
ngrok http 5000
```
# 실행 방법
먼저 main.py를 실행하고, 터미널에서 ngrok http 5000을 실행하면 서버가 정상적으로 실행됩니다.
