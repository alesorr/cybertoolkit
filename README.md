🔹 Solo file (zero CLI)
python main.py --workflow workflows/hotel.yaml --input-file inputs/hotel_bellavista.yaml

⸻
🔹 File + override veloce
python3 main.py \
 --workflow workflows/hotel.yaml \
 --input-file inputs/hotel_bellavista.yaml \
 --network 10.0.0.0/24