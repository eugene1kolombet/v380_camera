// v380.cpp — клиент IP-камеры V380 Pro для Windows (MSVC).
// Возможности: вход в камеру по LAN, привязка камеры к Wi-Fi, список записей
// с SD-карты, скачивание записи в mp4 (видео H.264 + аудио G.711 A-law).
//
// Зависимости — только Windows: Winsock2 (сеть), BCrypt (AES-128, SHA-256).
// X25519 встроен (TweetNaCl, public domain). Для сборки mp4 вызывается ffmpeg
// (если найден в PATH); иначе сохраняются сырые .h264 и .alaw.
//
// Сборка (из "x64 Native Tools Command Prompt for VS" или через vcvars64.bat):
//     cl /EHsc /O2 /W3 v380.cpp
//
// Протокол восстановлен из официального приложения; работает с вашей камерой
// в вашей локальной сети.

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

typedef unsigned char u8;
typedef uint32_t u32;
typedef std::vector<u8> Bytes;

// ===========================================================================
// Curve25519 (crypto_scalarmult) — TweetNaCl, public domain
// ===========================================================================
typedef long long i64;
typedef i64 gf[16];
static void car25519(gf o){int i;i64 c;for(i=0;i<16;i++){o[i]+=(1LL<<16);c=o[i]>>16;o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);o[i]-=c<<16;}}
static void sel25519(gf p,gf q,int b){i64 t,i,c=~(b-1);for(i=0;i<16;i++){t=c&(p[i]^q[i]);p[i]^=t;q[i]^=t;}}
static void pack25519(u8*o,const gf n){int i,j,b;gf m,t;for(i=0;i<16;i++)t[i]=n[i];car25519(t);car25519(t);car25519(t);for(j=0;j<2;j++){m[0]=t[0]-0xffed;for(i=1;i<15;i++){m[i]=t[i]-0xffff-((m[i-1]>>16)&1);m[i-1]&=0xffff;}m[15]=t[15]-0x7fff-((m[14]>>16)&1);b=(m[15]>>16)&1;m[14]&=0xffff;sel25519(t,m,1-b);}for(i=0;i<16;i++){o[2*i]=(u8)(t[i]&0xff);o[2*i+1]=(u8)(t[i]>>8);}}
static void unpack25519(gf o,const u8*n){int i;for(i=0;i<16;i++)o[i]=n[2*i]+((i64)n[2*i+1]<<8);o[15]&=0x7fff;}
static void A(gf o,const gf a,const gf b){int i;for(i=0;i<16;i++)o[i]=a[i]+b[i];}
static void Z(gf o,const gf a,const gf b){int i;for(i=0;i<16;i++)o[i]=a[i]-b[i];}
static void M(gf o,const gf a,const gf b){i64 i,j,t[31];for(i=0;i<31;i++)t[i]=0;for(i=0;i<16;i++)for(j=0;j<16;j++)t[i+j]+=a[i]*b[j];for(i=0;i<15;i++)t[i]+=38*t[i+16];for(i=0;i<16;i++)o[i]=t[i];car25519(o);car25519(o);}
static void S(gf o,const gf a){M(o,a,a);}
static void inv25519(gf o,const gf i){gf c;int a;for(a=0;a<16;a++)c[a]=i[a];for(a=253;a>=0;a--){S(c,c);if(a!=2&&a!=4)M(c,c,i);}for(a=0;a<16;a++)o[a]=c[a];}
static const gf _121665={0xDB41,1};
static int crypto_scalarmult(u8*q,const u8*n,const u8*p){u8 z[32];i64 x[80],r,i;gf a,b,c,d,e,f;for(i=0;i<31;i++)z[i]=n[i];z[31]=(n[31]&127)|64;z[0]&=248;unpack25519(x,p);for(i=0;i<16;i++){b[i]=x[i];d[i]=a[i]=c[i]=0;}a[0]=d[0]=1;for(i=254;i>=0;--i){r=(z[i>>3]>>(i&7))&1;sel25519(a,b,(int)r);sel25519(c,d,(int)r);A(e,a,c);Z(a,a,c);A(c,b,d);Z(b,b,d);S(d,e);S(f,a);M(a,c,a);M(c,b,e);A(e,a,c);Z(a,a,c);S(b,a);Z(c,d,f);M(a,c,_121665);A(a,a,d);M(c,c,a);M(a,d,f);M(d,b,x);S(b,e);sel25519(a,b,(int)r);sel25519(c,d,(int)r);}for(i=0;i<16;i++){x[i+16]=a[i];x[i+32]=c[i];x[i+48]=b[i];x[i+64]=d[i];}inv25519(x+32,x+32);M(x+16,x+16,x+32);pack25519(q,x+16);return 0;}
static int crypto_scalarmult_base(u8*q,const u8*n){static const u8 base[32]={9};return crypto_scalarmult(q,n,base);}

// ===========================================================================
// BCrypt: случайные байты, SHA-256, AES-128 (CBC без паддинга, ECB-блок)
// ===========================================================================
static void randBytes(u8* p, size_t n){ BCryptGenRandom(nullptr,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG); }

static Bytes sha256(const u8* data, size_t len){
    BCRYPT_ALG_HANDLE h=nullptr; BCRYPT_HASH_HANDLE hh=nullptr;
    BCryptOpenAlgorithmProvider(&h,BCRYPT_SHA256_ALGORITHM,nullptr,0);
    BCryptCreateHash(h,&hh,nullptr,0,nullptr,0,0);
    BCryptHashData(hh,(PUCHAR)data,(ULONG)len,0);
    Bytes out(32); BCryptFinishHash(hh,out.data(),32,0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(h,0);
    return out;
}

// AES-128-CBC без встроенного паддинга (данные кратны 16). iv не меняется у вызывающего.
static Bytes aesCbc(bool enc,const u8 key[16],const u8 iv[16],const u8* in,size_t inlen){
    BCRYPT_ALG_HANDLE h=nullptr; BCRYPT_KEY_HANDLE k=nullptr;
    BCryptOpenAlgorithmProvider(&h,BCRYPT_AES_ALGORITHM,nullptr,0);
    BCryptSetProperty(h,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0);
    BCryptGenerateSymmetricKey(h,&k,nullptr,0,(PUCHAR)key,16,0);
    u8 ivb[16]; memcpy(ivb,iv,16);
    ULONG cb=0; Bytes out(inlen?inlen:16);
    if(enc) BCryptEncrypt(k,(PUCHAR)in,(ULONG)inlen,nullptr,ivb,16,out.data(),(ULONG)out.size(),&cb,0);
    else    BCryptDecrypt(k,(PUCHAR)in,(ULONG)inlen,nullptr,ivb,16,out.data(),(ULONG)out.size(),&cb,0);
    out.resize(cb);
    BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(h,0);
    return out;
}

// Постоянный AES-ECB ключ для быстрой поблочной расшифровки кадров (ручной CBC).
struct AesEcb {
    BCRYPT_ALG_HANDLE h=nullptr; BCRYPT_KEY_HANDLE k=nullptr;
    void init(const u8 key[16]){
        BCryptOpenAlgorithmProvider(&h,BCRYPT_AES_ALGORITHM,nullptr,0);
        BCryptSetProperty(h,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_ECB,sizeof(BCRYPT_CHAIN_MODE_ECB),0);
        BCryptGenerateSymmetricKey(h,&k,nullptr,0,(PUCHAR)key,16,0);
    }
    void decBlock(const u8* in,u8* out){ ULONG cb=0; BCryptDecrypt(k,(PUCHAR)in,16,nullptr,nullptr,0,out,16,&cb,0); }
    ~AesEcb(){ if(k)BCryptDestroyKey(k); if(h)BCryptCloseAlgorithmProvider(h,0); }
};

static Bytes pkcs7pad(const Bytes& d){ size_t n=16-(d.size()%16); Bytes o=d; o.insert(o.end(),n,(u8)n); return o; }
static Bytes pkcs7unpad(const Bytes& d){ if(d.empty())return d; u8 n=d.back(); if(n>=1&&n<=16&&n<=d.size()){ bool ok=true; for(size_t i=0;i<n;i++) if(d[d.size()-1-i]!=n){ok=false;break;} if(ok) return Bytes(d.begin(),d.end()-n); } return d; }

// ===========================================================================
// Base64
// ===========================================================================
static const char* B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64enc(const u8* d,size_t n){
    std::string o; int v=0,bits=-6; for(size_t i=0;i<n;i++){ v=(v<<8)+d[i]; bits+=8; while(bits>=0){ o+=B64[(v>>bits)&0x3f]; bits-=6; } } if(bits>-6)o+=B64[((v<<8)>>(bits+8))&0x3f]; while(o.size()%4)o+='='; return o;
}
static Bytes b64dec(const std::string& s){
    int T[256]; for(int i=0;i<256;i++)T[i]=-1; for(int i=0;i<64;i++)T[(u8)B64[i]]=i;
    Bytes o; int v=0,bits=-8; for(char c:s){ if(c=='=')break; int t=T[(u8)c]; if(t<0)continue; v=(v<<6)+t; bits+=6; if(bits>=0){ o.push_back((u8)((v>>bits)&0xff)); bits-=8; } } return o;
}

// ===========================================================================
// Минимальный JSON-парсер
// ===========================================================================
struct JVal {
    enum T{OBJ,ARR,STR,NUM,BOOLV,NUL} t=NUL;
    std::map<std::string,JVal> obj; std::vector<JVal> arr; std::string str; double num=0; bool b=false;
    const JVal* get(const std::string& k) const { if(t==OBJ){auto it=obj.find(k); if(it!=obj.end())return &it->second;} return nullptr; }
    double n(double d=0) const { return t==NUM?num:d; }
    std::string s() const { return t==STR?str:std::string(); }
};
static void jskip(const char*&p){ while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r')p++; }
static JVal jparse(const char*&p);
static std::string jstr(const char*&p){ std::string o; p++; while(*p&&*p!='"'){ if(*p=='\\'){ p++; switch(*p){case 'n':o+='\n';break;case 't':o+='\t';break;case 'r':o+='\r';break;case '"':o+='"';break;case '\\':o+='\\';break;case '/':o+='/';break;case 'u':{p++;int c=0;for(int i=0;i<4&&*p;i++){char h=*p++;c=c*16+(h<='9'?h-'0':(h|32)-'a'+10);}p--;if(c<128)o+=(char)c;else if(c<2048){o+=(char)(0xC0|(c>>6));o+=(char)(0x80|(c&0x3f));}else{o+=(char)(0xE0|(c>>12));o+=(char)(0x80|((c>>6)&0x3f));o+=(char)(0x80|(c&0x3f));}break;}default:o+=*p;} p++; } else o+=*p++; } if(*p=='"')p++; return o; }
static JVal jparse(const char*&p){
    jskip(p); JVal v;
    if(*p=='{'){ v.t=JVal::OBJ; p++; jskip(p); if(*p=='}'){p++;return v;} while(*p){ jskip(p); std::string k=jstr(p); jskip(p); if(*p==':')p++; v.obj[k]=jparse(p); jskip(p); if(*p==','){p++;continue;} if(*p=='}'){p++;break;} break; } }
    else if(*p=='['){ v.t=JVal::ARR; p++; jskip(p); if(*p==']'){p++;return v;} while(*p){ v.arr.push_back(jparse(p)); jskip(p); if(*p==','){p++;continue;} if(*p==']'){p++;break;} break; } }
    else if(*p=='"'){ v.t=JVal::STR; v.str=jstr(p); }
    else if(*p=='t'){ v.t=JVal::BOOLV; v.b=true; p+=4; }
    else if(*p=='f'){ v.t=JVal::BOOLV; v.b=false; p+=5; }
    else if(*p=='n'){ v.t=JVal::NUL; p+=4; }
    else { v.t=JVal::NUM; char* e=nullptr; v.num=strtod(p,&e); p=e?e:p+1; }
    return v;
}

// ===========================================================================
// Константы протокола
// ===========================================================================
static const int CMD_COMMON_IOT   = 939722776;
static const int CMD_COMMON_MEDIA = 939722784;
static const int CMD_COMMON_NOTIFY= 939722786;
static const int M_LANPASS_REQ    = 196870;
static const int M_RECLIST_REQ    = 197152;
static const int M_REPLAY_CTRL     = 197154;
static const int M_ACTION_REQ      = 197384;
static const long DAID_NET_CONFIG  = (4<<16)|512; // 262656
static const int PORT_IOT = 8089;
static const char* AP_IP = "192.168.1.1";
// Статический ключ шифрования пакета обмена ключами (LoginHelper.i).
static const u8 HANDSHAKE_KEY[32] = {
 54,58,229,40,22,56,207,132,150,154,99,78,159,150,106,152,
 181,115,209,255,233,55,178,119,209,241,214,43,56,116,138,229 };

// ===========================================================================
// Сокет
// ===========================================================================
static SOCKET connectTo(const char* ip,int port){
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char ps[16]; sprintf(ps,"%d",port);
    if(getaddrinfo(ip,ps,&hints,&res)!=0) return INVALID_SOCKET;
    SOCKET s=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(s!=INVALID_SOCKET){ DWORD to=8000; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));
        if(connect(s,res->ai_addr,(int)res->ai_addrlen)!=0){ closesocket(s); s=INVALID_SOCKET; } }
    freeaddrinfo(res); return s;
}
static bool recvExact(SOCKET s,u8* buf,size_t n){ size_t g=0; while(g<n){ int r=recv(s,(char*)buf+g,(int)(n-g),0); if(r<=0)return false; g+=r; } return true; }
static void sendAll(SOCKET s,const u8* d,size_t n){ size_t sent=0; while(sent<n){ int r=send(s,(const char*)d+sent,(int)(n-sent),0); if(r<=0)break; sent+=r; } }

static void le32(u8* p,u32 v){ p[0]=v&0xff;p[1]=(v>>8)&0xff;p[2]=(v>>16)&0xff;p[3]=(v>>24)&0xff; }
static u32 rd32(const u8* p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((u32)p[3]<<24); }

// Собрать IoT-пакет: 16-байтный заголовок + AES-CBC(json, key) PKCS7.
static Bytes buildPacket(int method,const std::string& params,const u8 key[32],u8 b2,u8 b3){
    static u32 idctr=0; u32 id=(randBytes((u8*)&idctr,4),idctr)&0x7fffffff;
    char head[256];
    int n=sprintf(head,"{\"id\":%u,\"method_id\":%d,\"chn\":1,\"ts\":%lld,\"params\":",
                  id,method,(long long)time(nullptr));
    std::string js(head,head+n); js+=params; js+="}";
    Bytes pt(js.begin(),js.end()); pt=pkcs7pad(pt);
    Bytes enc=aesCbc(true,key,key+16,pt.data(),pt.size());
    Bytes pkt(16+enc.size(),0);
    le32(&pkt[0],(u32)CMD_COMMON_IOT); pkt[4]=1; pkt[5]=2; pkt[6]=b2; pkt[7]=b3; le32(&pkt[12],(u32)enc.size());
    memcpy(&pkt[16],enc.data(),enc.size());
    return pkt;
}
// Прочитать пакет: вернуть cmd, secure, тело (расшифрованное при IOT/NOTIFY), и JSON.
struct Pkt{ int cmd=0; u8 secure=0; Bytes body; std::string json; };
static bool readPacket(SOCKET s,const u8 key[32],Pkt& out){
    u8 h[16]; if(!recvExact(s,h,16))return false;
    out.cmd=(int)rd32(h); out.secure=h[5]; u32 ds=rd32(h+12);
    out.body.resize(ds); if(ds && !recvExact(s,out.body.data(),ds))return false;
    if((out.cmd==CMD_COMMON_IOT||out.cmd==CMD_COMMON_NOTIFY) && ds){
        Bytes dec=aesCbc(false,key,key+16,out.body.data(),out.body.size());
        dec=pkcs7unpad(dec); out.json.assign(dec.begin(),dec.end());
    }
    return true;
}

// Часовой пояс ПК в формате камеры: часы*100 + минуты (UTC+3 -> 300), как в приложении V380.
static int tzVal(){
    TIME_ZONE_INFORMATION tzi; DWORD r=GetTimeZoneInformation(&tzi);
    int bias=-(tzi.Bias + (r==TIME_ZONE_ID_DAYLIGHT?tzi.DaylightBias:0)); int a=abs(bias);
    return (bias<0?-1:1)*(a/60*100+a%60);
}

// ===========================================================================
// Протокол
// ===========================================================================
struct Session{ SOCKET s=INVALID_SOCKET; u8 key[32]={0}; int sid=0; };

static bool lanLogin(Session& ss,const char* password){
    u8 seed[32]; const char* al="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    u8 r[32]; randBytes(r,32); for(int i=0;i<32;i++) seed[i]=al[r[i]%62];
    u8 pub[32]; crypto_scalarmult_base(pub,seed);
    u8 magic; randBytes(&magic,1);
    u8 pubx[32]; for(int i=0;i<32;i++) pubx[i]=pub[i]^magic;
    std::string cKM=b64enc(pubx,32);
    Bytes cat(pubx,pubx+32); for(const char* p=password;*p;p++)cat.push_back((u8)*p);
    Bytes dig=sha256(cat.data(),cat.size()); std::string cS=b64enc(dig.data(),32);
    char params[512]; sprintf(params,"{\"act\":1,\"verify\":{\"cKM\":\"%s\",\"cS\":\"%s\",\"tz\":%d,\"ts\":%lld}}",
        cKM.c_str(),cS.c_str(),tzVal(),(long long)time(nullptr));
    Bytes pkt=buildPacket(M_LANPASS_REQ,params,HANDSHAKE_KEY,0,magic);
    sendAll(ss.s,pkt.data(),pkt.size());
    Pkt rp; if(!readPacket(ss.s,HANDSHAKE_KEY,rp)) return false;
    if(rp.cmd!=CMD_COMMON_IOT||rp.json.empty()){ printf("вход: неверный ответ камеры\n"); return false; }
    const char* jp=rp.json.c_str(); JVal j=jparse(jp);
    const JVal* data=j.get("data"); const JVal* verify=data?data->get("verify"):nullptr;
    if(!verify||!verify->get("dK")){ const JVal* res=j.get("result"); int code=res&&res->get("code")?(int)res->get("code")->n():0; printf("обмен ключами отклонён (код %d) — неверный пароль камеры?\n",code); return false; }
    Bytes dK=b64dec(verify->get("dK")->s());
    if(dK.size()<32){ printf("вход: короткий dK\n"); return false; }
    crypto_scalarmult(ss.key,seed,dK.data());
    ss.sid = verify->get("sid")?(int)verify->get("sid")->n():0;
    return true;
}

struct Seg{ long long startMs; double durS; int type; };
static bool listRecordings(Session& ss,std::vector<Seg>& out){
    long long now=(long long)time(nullptr)*1000;
    long long startMs=now-(long long)3650*24*3600*1000; long long endMs=now;
    char params[160]; sprintf(params,"{\"filter\":15,\"mode\":2,\"start\":%lld,\"end\":%lld}",startMs,endMs);
    Bytes pkt=buildPacket(M_RECLIST_REQ,params,ss.key,(u8)ss.sid,0);
    sendAll(ss.s,pkt.data(),pkt.size());
    for(;;){ Pkt rp; if(!readPacket(ss.s,ss.key,rp))break; if(rp.json.empty())break;
        const char* jp=rp.json.c_str(); JVal j=jparse(jp);
        const JVal* data=j.get("data"); if(!data)break;
        const JVal* lst=data->get("list");
        if(lst&&lst->t==JVal::ARR){ for(const JVal& it:lst->arr){
            long long s=(long long)(it.get("s")?it.get("s")->n():0);
            double d=(it.get("d")?it.get("d")->n():0)/1000.0;
            int t=it.get("t")?(int)it.get("t")->n():0;
            out.push_back({startMs+s,d,t}); } }
        const JVal* flag=data->get("flag"); if(!flag||flag->n()==0)break;
    }
    return true;
}

static bool provision(Session& ss,const char* ssid,const char* pw){
    std::string sb=b64enc((const u8*)ssid,strlen(ssid)), pb=b64enc((const u8*)pw,strlen(pw));
    char params[512]; sprintf(params,"{\"daid\":%ld,\"in\":{\"mode\":1,\"ssid\":\"%s\",\"pwd\":\"%s\"}}",
        DAID_NET_CONFIG,sb.c_str(),pb.c_str());
    Bytes pkt=buildPacket(M_ACTION_REQ,params,ss.key,(u8)ss.sid,0);
    sendAll(ss.s,pkt.data(),pkt.size());
    Pkt rp; if(readPacket(ss.s,ss.key,rp)&&!rp.json.empty()){
        const char* jp=rp.json.c_str(); JVal j=jparse(jp);
        const JVal* res=j.get("result"); int code=res&&res->get("code")?(int)res->get("code")->n():1000;
        if(code!=1000&&code!=0){ printf("камера вернула код %d\n",code); return false; }
    }
    return true;
}

// Расшифровка MEDIA-кадра: AES-128-CBC (key=sess[:16], iv=sess[16:32]), выборочно.
// Возвращает тип кадра (1=видео-I,2=видео-P,4=аудио) и payload.
static int frameDecrypt(const u8* body,size_t len,AesEcb& ecb,const u8 iv[16],Bytes& out){
    u8 prev[16]; memcpy(prev,iv,16);
    auto decReg=[&](const u8* d,size_t n){ for(size_t i=0;i+16<=n;i+=16){ u8 pt[16]; ecb.decBlock(d+i,pt); for(int k=0;k<16;k++) out.push_back(pt[k]^prev[k]); memcpy(prev,d+i,16);} };
    if(len<32)return 0;
    // заголовок (32 байта)
    Bytes hdr; { u8 ph[16]; memcpy(ph,iv,16); for(int i=0;i<32;i+=16){ u8 pt[16]; ecb.decBlock(body+i,pt); for(int k=0;k<16;k++)hdr.push_back(pt[k]^ph[k]); memcpy(ph,body+i,16);} memcpy(prev,body+16,16); }
    int ftype=hdr[1];
    u32 plen=rd32(&hdr[0x12]), elen=rd32(&hdr[0x16]), slen=rd32(&hdr[0x1a]);
    size_t pos=32; long long rem=(long long)len-32;
    auto copyPlain=[&](size_t n){ for(size_t i=0;i<n&&pos<len;i++) out.push_back(body[pos++]); };
    if((long long)plen<=rem){ copyPlain(plen); rem-=plen; } else { copyPlain((size_t)rem); return ftype; }
    while(elen>0 && rem>=(long long)elen){ decReg(body+pos,elen); pos+=elen; rem-=elen;
        size_t sk=(size_t)((rem<(long long)slen)?rem:slen); copyPlain(sk); rem-=sk; }
    if(rem>0) copyPlain((size_t)rem);
    return ftype;
}

static bool fileExists(const std::string& p){ DWORD a=GetFileAttributesA(p.c_str()); return a!=INVALID_FILE_ATTRIBUTES; }

static bool downloadSeg(Session& ss,const Seg& seg,const std::string& outMp4){
    AesEcb ecb; ecb.init(ss.key);
    auto req=[&](const std::string& params){ Bytes p=buildPacket(M_REPLAY_CTRL,params,ss.key,(u8)ss.sid,0); sendAll(ss.s,p.data(),p.size()); };
    char p0[256]; sprintf(p0,"{\"pts\":%lld,\"sts\":%lld,\"rtype\":%d,\"time_id\":1,\"vsspec\":0,\"frames\":100,\"video\":1,\"audio\":1}",
        seg.startMs,seg.startMs,seg.type);
    req(p0);
    Bytes video, audio; int nv=0,na=0; bool done=false;
    double limit=seg.durS+15; DWORD t0=GetTickCount();
    while(!done && (GetTickCount()-t0)/1000.0<limit){
        Pkt rp; if(!readPacket(ss.s,ss.key,rp))break;
        if(rp.cmd==CMD_COMMON_MEDIA){
            Bytes pl; int ft=frameDecrypt(rp.body.data(),rp.body.size(),ecb,ss.key+16,pl);
            if(ft==1||ft==2){ video.insert(video.end(),pl.begin(),pl.end()); nv++; }
            else if(ft==4){ audio.insert(audio.end(),pl.begin(),pl.end()); na++; }
        } else if(rp.cmd==CMD_COMMON_NOTIFY && !rp.json.empty()){
            const char* jp=rp.json.c_str(); JVal j=jparse(jp);
            const JVal* par=j.get("params"); int iid=par&&par->get("info_id")?(int)par->get("info_id")->n():0;
            if(iid==4) req("{\"time_id\":1,\"frames\":100}");
            else if(iid==3) done=true;
        }
        if(nv%100==0&&nv>0){ printf("\r  кадров видео: %d, аудио: %d   ",nv,na); fflush(stdout);}
    }
    printf("\r  получено: видео %d, аудио %d кадров        \n",nv,na);
    if(nv==0){ printf("кадры не получены\n"); return false; }
    int fps=seg.durS>0?(int)(nv/seg.durS+0.5):15; if(fps<1)fps=1;
    std::string vtmp=outMp4+".h264", atmp=outMp4+".alaw";
    { FILE* f=fopen(vtmp.c_str(),"wb"); if(f){ fwrite(video.data(),1,video.size(),f); fclose(f);} }
    if(!audio.empty()){ FILE* f=fopen(atmp.c_str(),"wb"); if(f){ fwrite(audio.data(),1,audio.size(),f); fclose(f);} }
    // мукс через ffmpeg, если он есть
    char cmd[2048];
    if(!audio.empty())
        sprintf(cmd,"ffmpeg -v error -y -r %d -i \"%s\" -f alaw -ar 16000 -ac 1 -i \"%s\" -map 0:v:0 -map 1:a:0 -c:v copy -c:a aac \"%s\"",
                fps,vtmp.c_str(),atmp.c_str(),outMp4.c_str());
    else
        sprintf(cmd,"ffmpeg -v error -y -r %d -i \"%s\" -c copy \"%s\"",fps,vtmp.c_str(),outMp4.c_str());
    int rc=system(cmd);
    if(rc==0 && fileExists(outMp4)){
        remove(vtmp.c_str()); if(!audio.empty())remove(atmp.c_str());
        printf("Готово: %d видеокадров (%d аудио) @ %d fps -> %s\n",nv,na,fps,outMp4.c_str());
    } else {
        printf("ffmpeg не найден/ошибка. Сохранены сырые потоки:\n  видео: %s (H.264, %d fps)\n",vtmp.c_str(),fps);
        if(!audio.empty()) printf("  аудио: %s (G.711 A-law, 16000 Гц моно)\n",atmp.c_str());
    }
    return true;
}

// ===========================================================================
// CLI
// ===========================================================================
static void usage(){
    printf(
"V380 — клиент IP-камеры (Windows).\n\n"
"Использование:\n"
"  v380 --ip <IP> --password <пароль_камеры> list\n"
"  v380 --ip <IP> --password <пароль_камеры> download --seg <N> --out <файл.mp4>\n"
"  v380 --password <пароль_камеры> provision --ssid <сеть> --wifi-password <пароль> [--ip 192.168.1.1]\n\n"
"Пароль камеры — с наклейки (Password). Для provision переведите камеру в режим AP\n"
"и подключите ПК к её Wi-Fi (адрес камеры по умолчанию 192.168.1.1).\n");
}

int main(int argc,char** argv){
    const char* ip=nullptr; const char* pw=""; const char* cmd=nullptr;
    const char* out="recording.mp4"; const char* ssid=nullptr; const char* wifipw="";
    int segN=0;
    for(int i=1;i<argc;i++){ std::string a=argv[i];
        auto nx=[&](const char* def)->const char*{ return (i+1<argc)?argv[++i]:def; };
        if(a=="--ip") ip=nx(ip);
        else if(a=="--password") pw=nx(pw);
        else if(a=="--out") out=nx(out);
        else if(a=="--seg") segN=atoi(nx("0"));
        else if(a=="--ssid") ssid=nx(nullptr);
        else if(a=="--wifi-password") wifipw=nx("");
        else if(a[0]!='-') cmd=argv[i];
    }
    if(!cmd){ usage(); return 1; }

    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    if(!ip && std::string(cmd)=="provision") ip=AP_IP;
    if(!ip){ printf("Укажите --ip камеры.\n"); return 1; }

    Session ss; ss.s=connectTo(ip,PORT_IOT);
    if(ss.s==INVALID_SOCKET){ printf("Не удалось подключиться к %s:%d\n",ip,PORT_IOT); return 1; }
    printf("Вхожу в камеру %s:%d ...\n",ip,PORT_IOT);
    if(!lanLogin(ss,pw)){ closesocket(ss.s); return 1; }
    printf("Вход выполнен (sid=%d).\n",ss.sid);

    int ret=0; std::string c=cmd;
    if(c=="list"){
        std::vector<Seg> segs; listRecordings(ss,segs);
        if(segs.empty()) printf("Записей не найдено.\n");
        for(size_t i=0;i<segs.size();i++){ time_t t=(time_t)(segs[i].startMs/1000); struct tm* tmv=localtime(&t); char b[32]; strftime(b,32,"%Y-%m-%d %H:%M:%S",tmv);
            const char* tn = segs[i].type==2?"движение/тревога":(segs[i].type==1?"по расписанию":"запись");
            printf("%3zu  %s  %6.1f c  %s\n",i,b,segs[i].durS,tn); }
        printf("Всего сегментов: %zu\n",segs.size());
    } else if(c=="download"){
        std::vector<Seg> segs; listRecordings(ss,segs);
        if(segs.empty()){ printf("Записей не найдено.\n"); ret=1; }
        else { if(segN>=(int)segs.size())segN=(int)segs.size()-1;
            time_t t=(time_t)(segs[segN].startMs/1000); struct tm* tmv=localtime(&t); char b[32]; strftime(b,32,"%Y-%m-%d %H:%M:%S",tmv);
            printf("Скачиваю запись %s (%.0f c)...\n",b,segs[segN].durS);
            if(!downloadSeg(ss,segs[segN],out)) ret=1; }
    } else if(c=="provision"){
        if(!ssid){ printf("Укажите --ssid.\n"); ret=1; }
        else { printf("Передаю камере сеть \"%s\" ...\n",ssid);
            if(provision(ss,ssid,wifipw)){ printf("Готово. Камера перезагрузится и подключится к \"%s\".\n",ssid);
                printf("Через ~30 сек найдите её в своей сети по IP из роутера.\n"); } else ret=1; }
    } else { usage(); ret=1; }

    closesocket(ss.s); WSACleanup();
    return ret;
}
