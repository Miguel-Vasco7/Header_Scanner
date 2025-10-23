import requests
import time

def security_headers_scanner(url):
    try:
        print("\033[91m" + "═" * 100)
        print("SECURITY HEADERS SCANNER - Powered by: Miguel Vasco ")
        print("═" * 100 + "\033[0m")
        
        print(f"\033[96m[*] Iniciando análise em: \033[95m{url}\033[0m")
        print("\033[96m[*] Coletando headers...\033[0m")
        time.sleep(1)
        
        r = requests.get(url, timeout=10)
        headers = r.headers
        
        print(f"\033[91m\n ANALISANDO TARGET: \033[93m{url}\033[0m")
        print("\033[91m" + "─" * 100 + "\033[0m")
        
        # ALTA PRIORIDADE - CRÍTICO
        print("\n\033[91m ALTA PRIORIDADE [CRITICAL]\033[0m")
        print("\033[91m" + "─" * 100 + "\033[0m")
        
        if 'X-Frame-Options' not in headers:
            print(' \033[91mCLICKJACKING DETECTADO    → \033[92m<iframe src="target.com">\033[0m')
        else:
            print(' \033[92mX-Frame-Options          → \033[94m[PROTEGIDO]\033[0m')
            
        if 'Content-Security-Policy' not in headers:  
            print(' \033[91mXSS VULNERABILITY         → \033[92m<script>alert(1)</script>\033[0m')
        else:
            print(' \033[92mContent-Security-Policy   → \033[94m[PROTEGIDO]\033[0m')
            
        if 'Strict-Transport-Security' not in headers:
            print(' \033[91mSSL STRIP ATTACK          → \033[92mMan-in-the-Middle\033[0m')
        else:
            print(' \033[92mStrict-Transport-Security → \033[94m[PROTEGIDO]\033[0m')
            
        if 'X-Content-Type-Options' not in headers:
            print(' \033[91mMIME SNIFFING             → \033[92mUpload Malicioso\033[0m')
        else:
            print(' \033[92mX-Content-Type-Options    → \033[94m[PROTEGIDO]\033[0m')

        # VERIFICAÇÃO DE COOKIES
        print("\n\033[93m COOKIES ANALYSIS\033[0m")
        print("\033[93m" + "─" * 100 + "\033[0m")
        cookie_vulns = False
        for cookie in r.cookies:
            if not cookie.secure:
                print(' \033[91mSESSION HIJACKING        → \033[92mCookie sem Secure flag\033[0m')
                cookie_vulns = True
            if not hasattr(cookie, 'httponly') or not getattr(cookie, 'httponly', False):
                print(' \033[91mXSS COOKIE THEFT         → \033[92mCookie sem HttpOnly\033[0m')
                cookie_vulns = True
        if not cookie_vulns:
            print(' \033[92mCookies Security          → \033[94m[SECURE & HTTPONLY]\033[0m')

        # MÉDIA PRIORIDADE
        print("\n\033[93m  MÉDIA PRIORIDADE [WARNING]\033[0m")
        print("\033[93m" + "─" * 100 + "\033[0m")
        
        if 'Referrer-Policy' not in headers:
            print('  \033[93mINFORMATION LEAK          → \033[92mVaza URLs sensíveis\033[0m')
        else:
            print(' \033[92mReferrer-Policy           → \033[94m[PROTEGIDO]\033[0m')
            
        if 'X-XSS-Protection' not in headers:
            print('  \033[93mXSS PROTECTION            → \033[92mBrowser protection off\033[0m')
        else:
            print(' \033[92mX-XSS-Protection          → \033[94m[PROTEGIDO]\033[0m')
            
        if 'Feature-Policy' not in headers and 'Permissions-Policy' not in headers:
            print('  \033[93mFEATURE POLICY            → \033[92mFeature abuse possível\033[0m')
        else:
            print(' \033[92mFeature-Policy            → \033[94m[PROTEGIDO]\033[0m')

        # INFORMATION DISCLOSURE
        print("\n\033[96m INFORMATION DISCLOSURE\033[0m")
        print("\033[96m" + "─" * 100 + "\033[0m")
        info_leaks = False
        if 'Server' in headers:
            print(f' \033[96mSERVER LEAK              → \033[93m{headers["Server"]}\033[0m')
            info_leaks = True
        if 'X-Powered-By' in headers:
            print(f' \033[96mPOWERED BY LEAK          → \033[93m{headers["X-Powered-By"]}\033[0m')
            info_leaks = True
        if 'X-AspNet-Version' in headers:
            print(f' \033[96mASP.NET LEAK             → \033[93m{headers["X-AspNet-Version"]}\033[0m')
            info_leaks = True
        if not info_leaks:
            print(' \033[92mInformation Disclosure    → \033[94m[PROTEGIDO]\033[0m')

        # RESUMO FINAL
        print("\n\033[95m" + "═" * 100)
        print(" SCAN COMPLETE - RESUMO DO TARGET")
        print("═" * 100 + "\033[0m")
        print(" \033[92mProtegido     \033[91mVulnerável      \033[93mWarning\033[0m")
        print("\033[95m" + "─" * 100 + "\033[0m")
        print(" \033[96mDica: Foque nas vulnerabilidades em \033[91mVERMELHO\033[96m para bug bounty!\033[0m")
        print("\033[91m" + "═" * 100 + "\033[0m")

    except requests.exceptions.RequestException as e:
        print(f"\n \033[91mERRO: Falha ao acessar o target → {e}\033[0m")

# USO DA FERRAMENTA
if __name__ == "__main__":
    #print("\033[91m" + "" * 60)
    print("\033[93m                   HEADER SECURITY SCANNER                    \033[0m")
    print("\033[93m                   HACKER ÉTICO - MIGUEL VASCO            \033[0m")
    
    url = input("\n \033[91mDigite o target URL (ex: https://alvo.com): \033[0m")
    security_headers_scanner(url)