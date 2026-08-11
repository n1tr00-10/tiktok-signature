from x_gnarly import get_X_Gnarly
from x_bogus import get_X_Bogus
from x_dynosaur import get_X_Dynosaur

def main():
    # Common parameters
    query = "aid=1988&app_name=tiktok_web"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    print("=" * 50)
    print("TikTok Signature Generator - Basic Example")
    print("=" * 50)
    
    # 1. X-Gnarly
    print("\n[1] Generating X-Gnarly")
    gnarly = get_X_Gnarly(query, "", user_agent, version='5.1.2')
    print(f"X-Gnarly: {gnarly}")
    
    # 2. X-Bogus
    print("\n[2] Generating X-Bogus")
    url = f"https://www.tiktok.com/api/v1/feed?{query}"
    bogus = get_X_Bogus(url, "", "")
    print(f"X-Bogus: {bogus}")
    
    # 3. X-Dynosaur
    print("\n[3] Generating X-Dynosaur...")
    dynosaur = get_X_Dynosaur(query, user_agent)
    print(f"X-Dynosaur: {dynosaur}")
    
    print("\n" + "=" * 50)
    print("Done")

if __name__ == "__main__":
    main()
