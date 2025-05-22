import pandas as pd
import numpy as np
from collections import defaultdict
from flask import Flask, request, render_template, send_file  # Sử dụng render_template
import os
from werkzeug.utils import secure_filename
import joblib
import io
from elasticsearch import Elasticsearch, helpers
import csv
from flask import redirect, url_for
from flask import flash, get_flashed_messages


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Thay bằng chuỗi bất kỳ

# Thư mục để lưu file tải lên và file kết quả
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER


# Kết nối Elasticsearch
es = Elasticsearch(
    "https://localhost:9200",
    verify_certs=False,
    basic_auth=("elastic", "CP=Gmq7Q8Rd0n02E-_W4")  # Thay bằng thông tin xác thực của bạn
)
# Tạo thư mục nếu chưa tồn tại
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# Load mô hình và scaler
scaler_path = r"model/scaler_71_features.pkl"
model_path = r"model/xgboost_best_model_71_features.pkl"

scaler = joblib.load(scaler_path)
model = joblib.load(model_path)

# Danh sách các cột đặc trưng cần thiết (bạn cần thay bằng đúng 69 đặc trưng)
expected_features = scaler.feature_names_in_.tolist()  # nếu bạn dùng sklearn >= 1.0

# Hàm tính toán 69 đặc trưng từ dữ liệu
def calculate_features(df):
    # Nhóm các gói tin thành luồng (dựa trên 5-tuple: Src IP, Dst IP, Src Port, Dst Port, Protocol)
    flows = defaultdict(list)
    for idx, row in df.iterrows():
        flow_key = (row["Source"], row["Destination"], row["Source Port"], row["Destination Port"], row["Protocol"])
        flows[flow_key].append(row)

    # Tính toán các đặc trưng cho từng luồng
    flow_features = []
    for flow_key, packets in flows.items():
        packets = pd.DataFrame(packets)
        
        # Flow Duration
        flow_duration = packets["Time"].max() - packets["Time"].min()
        
        # Xác định gói tin Fwd và Bwd (dựa trên Source/Destination IP)
        src_ip = flow_key[0]
        fwd_packets = packets[packets["Source"] == src_ip]
        bwd_packets = packets[packets["Source"] != src_ip]
        
        # Total Fwd Packets và Total Backward Packets
        total_fwd_packets = len(fwd_packets)
        total_bwd_packets = len(bwd_packets)
        
        # Total Length of Fwd Packets và Total Length of Bwd Packets
        total_length_fwd = fwd_packets["Length"].sum()
        total_length_bwd = bwd_packets["Length"].sum()
        
        # Fwd Packet Length Mean và Bwd Packet Length Mean
        fwd_packet_len_mean = fwd_packets["Length"].mean() if total_fwd_packets > 0 else 0
        bwd_packet_len_mean = bwd_packets["Length"].mean() if total_bwd_packets > 0 else 0
        
        # Flow Bytes/s
        flow_bytes_s = (total_length_fwd + total_length_bwd) / flow_duration if flow_duration > 0 else 0
        
        # Flow Packets/s
        flow_packets_s = (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0
        
        # Flow IAT Max, Flow IAT Min
        packet_times = packets["Time"].sort_values()
        iat = packet_times.diff().dropna()
        flow_iat_max = iat.max() if len(iat) > 0 else 0
        flow_iat_min = iat.min() if len(iat) > 0 else 0
        
        # Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min
        fwd_times = fwd_packets["Time"].sort_values()
        fwd_iat = fwd_times.diff().dropna()
        fwd_iat_total = fwd_times.max() - fwd_times.min() if len(fwd_times) > 1 else 0
        fwd_iat_mean = fwd_iat.mean() if len(fwd_iat) > 0 else 0
        fwd_iat_std = fwd_iat.std() if len(fwd_iat) > 0 else 0
        fwd_iat_max = fwd_iat.max() if len(fwd_iat) > 0 else 0
        fwd_iat_min = fwd_iat.min() if len(fwd_iat) > 0 else 0
        
        # Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min
        bwd_times = bwd_packets["Time"].sort_values()
        bwd_iat = bwd_times.diff().dropna()
        bwd_iat_total = bwd_times.max() - bwd_times.min() if len(bwd_times) > 1 else 0
        bwd_iat_mean = bwd_iat.mean() if len(bwd_iat) > 0 else 0
        bwd_iat_std = bwd_iat.std() if len(bwd_iat) > 0 else 0
        bwd_iat_max = bwd_iat.max() if len(bwd_iat) > 0 else 0
        bwd_iat_min = bwd_iat.min() if len(bwd_iat) > 0 else 0
        
        # Đếm các cờ (Flags)
        fwd_psh_flags = fwd_packets["Flags"].str.contains("PSH", na=False).sum()
        bwd_psh_flags = bwd_packets["Flags"].str.contains("PSH", na=False).sum()
        fwd_urg_flags = fwd_packets["Flags"].str.contains("URG", na=False).sum()
        bwd_urg_flags = bwd_packets["Flags"].str.contains("URG", na=False).sum()
        fin_flag_count = packets["Flags"].str.contains("FIN", na=False).sum()
        syn_flag_count = packets["Flags"].str.contains("SYN", na=False).sum()
        rst_flag_count = packets["Flags"].str.contains("RST", na=False).sum()
        psh_flag_count = packets["Flags"].str.contains("PSH", na=False).sum()
        ack_flag_count = packets["Flags"].str.contains("ACK", na=False).sum()
        urg_flag_count = packets["Flags"].str.contains("URG", na=False).sum()
        cwe_flag_count = packets["Flags"].str.contains("CWE", na=False).sum()
        ece_flag_count = packets["Flags"].str.contains("ECE", na=False).sum()
        
        # Fwd Header Length và Bwd Header Length (giả sử header length = 20 bytes cho TCP/IP)
        fwd_header_length = total_fwd_packets * 20
        bwd_header_length = total_bwd_packets * 20
        
        # Fwd Packets/s và Bwd Packets/s
        fwd_packets_s = total_fwd_packets / flow_duration if flow_duration > 0 else 0
        bwd_packets_s = total_bwd_packets / flow_duration if flow_duration > 0 else 0
        
        # Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance
        all_lengths = packets["Length"]
        min_packet_length = all_lengths.min() if len(all_lengths) > 0 else 0
        max_packet_length = all_lengths.max() if len(all_lengths) > 0 else 0
        packet_length_mean = all_lengths.mean() if len(all_lengths) > 0 else 0
        packet_length_std = all_lengths.std() if len(all_lengths) > 0 else 0
        packet_length_variance = all_lengths.var() if len(all_lengths) > 0 else 0
        
        # Down/Up Ratio
        down_up_ratio = total_bwd_packets / (total_fwd_packets + 1e-6)  # Tránh chia cho 0
        
        # Average Packet Size
        average_packet_size = all_lengths.mean() if len(all_lengths) > 0 else 0
        
        # Avg Fwd Segment Size và Avg Bwd Segment Size
        avg_fwd_segment_size = fwd_packet_len_mean
        avg_bwd_segment_size = bwd_packet_len_mean
        
        # Fwd Header Length.1 (giả sử giống Fwd Header Length)
        fwd_header_length_1 = fwd_header_length
        
        # Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate
        fwd_avg_bytes_bulk = 0
        fwd_avg_packets_bulk = 0
        fwd_avg_bulk_rate = 0
        
        # Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0
        bwd_avg_bulk_rate = 0
        
        # Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes
        subflow_fwd_packets = total_fwd_packets
        subflow_fwd_bytes = total_length_fwd
        subflow_bwd_packets = total_bwd_packets
        subflow_bwd_bytes = total_length_bwd
        
        # Init_Win_bytes_forward và Init_Win_bytes_backward
        init_win_bytes_forward = -1
        init_win_bytes_backward = -1
        
        # act_data_pkt_fwd
        act_data_pkt_fwd = len(fwd_packets[fwd_packets["Length"] > 0])
        
        # min_seg_size_forward (giả sử bằng 20, giống header length)
        min_seg_size_forward = 20
        
        # Active Mean, Active Std, Active Max, Active Min
        active_mean = 0
        active_std = 0
        active_max = 0
        active_min = 0
        
        # Idle Mean, Idle Std, Idle Max, Idle Min
        idle_mean = 0
        idle_std = 0
        idle_max = 0
        idle_min = 0
        
        # Tạo dictionary cho luồng này với đúng 69 đặc trưng
        flow_features.append({
            "Flow Duration": flow_duration,
            "Total Fwd Packets": total_fwd_packets,
            "Total Backward Packets": total_bwd_packets,
            "Total Length of Fwd Packets": total_length_fwd,
            "Total Length of Bwd Packets": total_length_bwd,
            "Fwd Packet Length Mean": fwd_packet_len_mean,
            "Bwd Packet Length Mean": bwd_packet_len_mean,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_packets_s,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": fwd_psh_flags,
            "Bwd PSH Flags": bwd_psh_flags,
            "Fwd URG Flags": fwd_urg_flags,
            "Bwd URG Flags": bwd_urg_flags,
            "Fwd Header Length": fwd_header_length,
            "Bwd Header Length": bwd_header_length,
            "Fwd Packets/s": fwd_packets_s,
            "Bwd Packets/s": bwd_packets_s,
            "Min Packet Length": min_packet_length,
            "Max Packet Length": max_packet_length,
            "Packet Length Mean": packet_length_mean,
            "Packet Length Std": packet_length_std,
            "Packet Length Variance": packet_length_variance,
            "FIN Flag Count": fin_flag_count,
            "SYN Flag Count": syn_flag_count,
            "RST Flag Count": rst_flag_count,
            "PSH Flag Count": psh_flag_count,
            "ACK Flag Count": ack_flag_count,
            "URG Flag Count": urg_flag_count,
            "CWE Flag Count": cwe_flag_count,
            "ECE Flag Count": ece_flag_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": average_packet_size,
            "Avg Fwd Segment Size": avg_fwd_segment_size,
            "Avg Bwd Segment Size": avg_bwd_segment_size,
            "Fwd Header Length.1": fwd_header_length_1,
            "Fwd Avg Bytes/Bulk": fwd_avg_bytes_bulk,
            "Fwd Avg Packets/Bulk": fwd_avg_packets_bulk,
            "Fwd Avg Bulk Rate": fwd_avg_bulk_rate,
            "Bwd Avg Bytes/Bulk": bwd_avg_bytes_bulk,
            "Bwd Avg Packets/Bulk": bwd_avg_packets_bulk,
            "Bwd Avg Bulk Rate": bwd_avg_bulk_rate,
            "Subflow Fwd Packets": subflow_fwd_packets,
            "Subflow Fwd Bytes": subflow_fwd_bytes,
            "Subflow Bwd Packets": subflow_bwd_packets,
            "Subflow Bwd Bytes": subflow_bwd_bytes,
            "Init_Win_bytes_forward": init_win_bytes_forward,
            "Init_Win_bytes_backward": init_win_bytes_backward,
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "min_seg_size_forward": min_seg_size_forward,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min
        })

    return pd.DataFrame(flow_features)

# Route cho trang chính
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Kiểm tra xem có file được tải lên không
        if 'file' not in request.files:
            return render_template('index.html', error="Không tìm thấy file. Vui lòng chọn file để tải lên.")
        
        file = request.files['file']
        
        # Kiểm tra xem người dùng có chọn file không
        if file.filename == '':
            return render_template('index.html', error="Không có file nào được chọn.")
        
        if file and file.filename.endswith('.csv'):
            # Lưu file tải lên
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Đọc file CSV
                df = pd.read_csv(filepath)
                
                # Kiểm tra các cột cần thiết
                required_columns = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Source Port", "Destination Port", "Flags", "Info"]
                missing_columns = [col for col in required_columns if col not in df.columns]
                if missing_columns:
                    return render_template('index.html', error=f"File CSV thiếu các cột: {', '.join(missing_columns)}")
                
                # Tính toán đặc trưng
                df_flows = calculate_features(df)
                
                # Lưu kết quả vào file CSV
                output_filename = f"flow_features_69_{filename}"
                output_filepath = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
                df_flows.to_csv(output_filepath, index=False)
                
                # Trả về file để tải xuống
                return send_file(
                    output_filepath,
                    as_attachment=True,
                    download_name=output_filename,
                    mimetype='text/csv'
                )
            
            except Exception as e:
                return render_template('index.html', error=f"Có lỗi xảy ra: {str(e)}")
            
            finally:
                # Xóa file tải lên sau khi xử lý
                if os.path.exists(filepath):
                    os.remove(filepath)
        
        else:
            return render_template('index.html', error="Vui lòng tải lên file CSV.")
    
    # Hiển thị giao diện nếu là GET request
    return render_template('index.html')

# Route để xóa file đầu ra sau khi tải xuống
@app.route('/delete/<filename>')
def delete_file(filename):
    filepath = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    return '', 204


# @app.route('/predict', methods=['POST'])
# def predict():
#     file = request.files['file']
#     if not file:
#         return "⚠️ Không có file được tải lên!"

#     df = pd.read_csv(file)

#     if list(df.columns) != expected_features:
#         return f"⚠️ Cột không khớp!<br>File cần có 69 đặc trưng như sau:<br>{expected_features}"

#     # Chuẩn hóa và dự đoán
#     X_new = scaler.transform(df)
#     predictions = model.predict(X_new)
#     probabilities = model.predict_proba(X_new)[:, 1]

#     # Chuẩn bị kết quả
#     results = []
#     for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
#         predicted_class = "Keylogger" if pred == 1 else "Benign"
#         results.append({
#             'Flow': i + 1,
#             'Class': predicted_class,
#             'Probability': round(prob, 4)
#         })

#     result_df = pd.DataFrame(results)

#     output = io.StringIO()
#     result_df.to_csv(output, index=False)
#     output.seek(0)

#     # Trả về file CSV để người dùng tải về
#     return send_file(output, as_attachment=True, download_name="prediction_results.csv", mimetype="text/csv")


# Route hiển thị kết quả dự đoán
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        # Xử lý tải lên và dự đoán
        file = request.files['file']
        if not file:
            return "⚠️ Không có file được tải lên!"

        df = pd.read_csv(file)
        # Kiểm tra cột và dự đoán như bạn đã làm trước
        if list(df.columns) != expected_features:
            return f"⚠️ Cột không khớp!<br>File cần có 69 đặc trưng như sau:<br>{expected_features}"

        # Chuẩn hóa và dự đoán
        X_new = scaler.transform(df)
        predictions = model.predict(X_new)
        probabilities = model.predict_proba(X_new)[:, 1]

        results = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            predicted_class = "Keylogger" if pred == 1 else "Benign"
            results.append({
                'flow': i + 1,
                'class': predicted_class,
                'probability': round(prob, 4)
            })

        global prediction_results
        prediction_results = results

        return render_template('result.html', results=results)
    
    # Xử lý khi là GET request, trả về kết quả đã có
    return render_template('result.html', results=prediction_results)


# Route để tải lên file CSV và gửi đến Elasticsearch
@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    file = request.files['file']
    if not file:
        return "⚠️ Không có file được tải lên!"

    # Đọc file CSV từ form
    file_content = file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(file_content))

    print("🧾 Các cột trong CSV:", reader.fieldnames)

    actions = [
        {
            "_index": "network_logvs2",
            "_source": {
                "Flow": int(row["Flow"]),
                "Class": row["Class"],
                "Probability": float(row["Probability(Keylogger)"])
            }
        }
        for row in reader
    ]

    # Gửi dữ liệu bulk lên Elasticsearch
    helpers.bulk(es, actions)
    print("✅ Đã upload thành công dữ liệu vào Elasticsearch.")
    flash("✅ Tải lên và gửi dữ liệu đến Elasticsearch thành công!", "success")

    return redirect(url_for('predict'))  # Sau khi upload xong, quay lại trang dự đoán


@app.route('/dowloadcsv')
def dowloadcsv():
    global prediction_results
    if not prediction_results:
        return "❌ Không có kết quả để tải!"

    # Tạo DataFrame từ prediction_results
    df = pd.DataFrame(prediction_results)

    # Đổi tên cột cho khớp với bảng HTML
    df = df.rename(columns={
        'flow': 'Flow',
        'class': 'Class',
        'probability': 'Probability(Keylogger)'
    })

    # Ghi ra CSV trong bộ nhớ
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='du_doan_keylogger.csv'
    )

if __name__ == '__main__':
    app.run(debug=True)