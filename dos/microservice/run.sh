docker build -t vulnerable-microservice .

docker run -d \
  --name microservice \
  --network dosnet \
  --cpus="0.2" \
  --memory="100m" \
  -p 5000:5000 \
  -v $(pwd):/app \
  vulnerable-microservice
