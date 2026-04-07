from flask import Flask, request, jsonify, make_response
import jwt
from datetime import datetime

app = Flask(__name__)

# --- CẤU HÌNH DEMO ---
# Chuyển thành True nếu muốn hệ thống luôn cho qua để xem trang Nginx
FORCE_ALLOW_FOR_DEMO = False 

def verify_zero_trust_policy(payload):
    # 1. Lấy dữ liệu từ Token
    user_clearance = payload.get('clearance')
    allowed_hours_str = payload.get('allowed_hours')
    username = payload.get('preferred_username', 'Unknown')
    
    # Lấy giờ hệ thống hiện tại
    current_hour = datetime.now().hour
    
    print(f"--- [DEBUG] Kiểm tra User: {username} ---")
    print(f"    + Clearance trong Token: {user_clearance}")
    print(f"    + Giờ cho phép trong Token: {allowed_hours_str}")
    print(f"    + Giờ hệ thống lúc này: {current_hour}h")

    # 2. Kiểm tra nếu Token thiếu dữ liệu (Do chưa cấu hình Keycloak Mapper)
    if not user_clearance or not allowed_hours_str:
        return False, "Thiếu trường 'clearance' hoặc 'allowed_hours' trong Token (Cần check Keycloak)"

    # 3. Logic so khớp Policy (ABAC)
    try:
        # Tách chuỗi "0-23" thành start=0, end=23
        start_hour, end_hour = map(int, allowed_hours_str.split('-'))
        
        # ĐIỀU KIỆN: Phải là 'action1' VÀ nằm trong khung giờ cho phép
        if user_clearance == 'action1' and (start_hour <= current_hour <= end_hour):
            return True, f"Hợp lệ! Chào mừng {username}."
        else:
            return False, f"Vi phạm Policy: Clearance={user_clearance}, Giờ hiện tại={current_hour}h"
            
    except Exception as e:
        return False, f"Lỗi định dạng giờ: {str(e)}"

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def auth(path):
    print(f"\n[PDP] >>> Đã nhận yêu cầu!")
    
    # IN THỬ HEADER ĐỂ XEM POSTMAN GỬI GÌ
    auth_header = request.headers.get('Authorization')
    print(f"    + Header nhận được: {auth_header}") # <--- Dòng này sẽ cứu bạn!
    
    if not auth_header:
        print("[PDP] <<< KẾT QUẢ: CHẶN (Vì Header Authorization đang trống rỗng)")
        return make_response(jsonify({"status": "Missing Header"}), 401)

    try:
        # Giải mã Token (Không check signature để Demo cho nhanh)
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Gọi hàm kiểm tra chính sách
        is_allowed, message = verify_zero_trust_policy(payload)
        
        # KIỂM TRA CHẾ ĐỘ FORCE ALLOW
        if FORCE_ALLOW_FOR_DEMO:
            print(f"[PDP] !!! CHẾ ĐỘ DEMO ĐANG BẬT: Bỏ qua lỗi và cho phép truy cập.")
            return make_response(jsonify({"status": "OK", "info": "Demo Mode"}), 200)

        if is_allowed:
            print(f"[PDP] <<< KẾT QUẢ: CHO QUA. ({message})")
            return make_response(jsonify({"status": "OK"}), 200)
        else:
            print(f"[PDP] <<< KẾT QUẢ: TỪ CHỐI. ({message})")
            # Trả về 403 để Envoy chặn lại
            return make_response(jsonify({"status": "Forbidden", "reason": message}), 403)
            
    except Exception as e:
        print(f"[PDP] <<< LỖI: {str(e)}")
        return make_response(jsonify({"status": "Error"}), 500)

if __name__ == '__main__':
    print("--- PDP SERVER ĐANG CHẠY TRÊN PORT 5000 ---")
    app.run(host='0.0.0.0', port=5000)