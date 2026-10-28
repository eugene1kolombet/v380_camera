// v380gui.cpp — оконное приложение для камеры V380 Pro (Windows/MSVC).
// Показывает записи с SD-карты в таблице (библиотека Windows Common Controls,
// элемент ListView) и скачивает выбранную запись в mp4.
//
// Сборка (из "x64 Native Tools Command Prompt for VS" или через build.bat):
//     cl /EHsc /O2 /DUNICODE /D_UNICODE v380gui.cpp
//
// Зависимости — только Windows: Winsock2, BCrypt, ComCtl32, Shell32.
// X25519 встроен (TweetNaCl). Для сборки mp4 вызывается ffmpeg (если в PATH).

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <mmsystem.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <process.h>
#include <deque>
#include <mutex>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winmm.lib")
// Включить визуальные стили (современный вид ListView/кнопок).
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

typedef unsigned char u8; typedef uint32_t u32; typedef std::vector<u8> Bytes;

// ===================== Curve25519 (TweetNaCl, public domain) =====================
typedef long long i64; typedef i64 gf[16];
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

// ===================== BCrypt: random, sha256, aes =====================
static void randBytes(u8*p,size_t n){BCryptGenRandom(nullptr,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG);}
static Bytes sha256(const u8*d,size_t l){BCRYPT_ALG_HANDLE h=nullptr;BCRYPT_HASH_HANDLE hh=nullptr;BCryptOpenAlgorithmProvider(&h,BCRYPT_SHA256_ALGORITHM,nullptr,0);BCryptCreateHash(h,&hh,nullptr,0,nullptr,0,0);BCryptHashData(hh,(PUCHAR)d,(ULONG)l,0);Bytes o(32);BCryptFinishHash(hh,o.data(),32,0);BCryptDestroyHash(hh);BCryptCloseAlgorithmProvider(h,0);return o;}
static Bytes aesCbc(bool enc,const u8 key[16],const u8 iv[16],const u8*in,size_t inlen){BCRYPT_ALG_HANDLE h=nullptr;BCRYPT_KEY_HANDLE k=nullptr;BCryptOpenAlgorithmProvider(&h,BCRYPT_AES_ALGORITHM,nullptr,0);BCryptSetProperty(h,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0);BCryptGenerateSymmetricKey(h,&k,nullptr,0,(PUCHAR)key,16,0);u8 ivb[16];memcpy(ivb,iv,16);ULONG cb=0;Bytes o(inlen?inlen:16);if(enc)BCryptEncrypt(k,(PUCHAR)in,(ULONG)inlen,nullptr,ivb,16,o.data(),(ULONG)o.size(),&cb,0);else BCryptDecrypt(k,(PUCHAR)in,(ULONG)inlen,nullptr,ivb,16,o.data(),(ULONG)o.size(),&cb,0);o.resize(cb);BCryptDestroyKey(k);BCryptCloseAlgorithmProvider(h,0);return o;}
struct AesEcb{BCRYPT_ALG_HANDLE h=nullptr;BCRYPT_KEY_HANDLE k=nullptr;void init(const u8 key[16]){BCryptOpenAlgorithmProvider(&h,BCRYPT_AES_ALGORITHM,nullptr,0);BCryptSetProperty(h,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_ECB,sizeof(BCRYPT_CHAIN_MODE_ECB),0);BCryptGenerateSymmetricKey(h,&k,nullptr,0,(PUCHAR)key,16,0);}void decBlock(const u8*in,u8*out){ULONG cb=0;BCryptDecrypt(k,(PUCHAR)in,16,nullptr,nullptr,0,out,16,&cb,0);}~AesEcb(){if(k)BCryptDestroyKey(k);if(h)BCryptCloseAlgorithmProvider(h,0);}};
static Bytes pkcs7pad(const Bytes&d){size_t n=16-(d.size()%16);Bytes o=d;o.insert(o.end(),n,(u8)n);return o;}
static Bytes pkcs7unpad(const Bytes&d){if(d.empty())return d;u8 n=d.back();if(n>=1&&n<=16&&n<=d.size()){bool ok=true;for(size_t i=0;i<n;i++)if(d[d.size()-1-i]!=n){ok=false;break;}if(ok)return Bytes(d.begin(),d.end()-n);}return d;}

// ===================== Base64 =====================
static const char*B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64enc(const u8*d,size_t n){std::string o;int v=0,bits=-6;for(size_t i=0;i<n;i++){v=(v<<8)+d[i];bits+=8;while(bits>=0){o+=B64[(v>>bits)&0x3f];bits-=6;}}if(bits>-6)o+=B64[((v<<8)>>(bits+8))&0x3f];while(o.size()%4)o+='=';return o;}
static Bytes b64dec(const std::string&s){int T[256];for(int i=0;i<256;i++)T[i]=-1;for(int i=0;i<64;i++)T[(u8)B64[i]]=i;Bytes o;int v=0,bits=-8;for(char c:s){if(c=='=')break;int t=T[(u8)c];if(t<0)continue;v=(v<<6)+t;bits+=6;if(bits>=0){o.push_back((u8)((v>>bits)&0xff));bits-=8;}}return o;}

// ===================== Минимальный JSON =====================
struct JVal{enum T{OBJ,ARR,STR,NUM,BOOLV,NUL}t=NUL;std::map<std::string,JVal>obj;std::vector<JVal>arr;std::string str;double num=0;bool b=false;const JVal*get(const std::string&k)const{if(t==OBJ){auto it=obj.find(k);if(it!=obj.end())return &it->second;}return nullptr;}double n(double d=0)const{return t==NUM?num:d;}std::string s()const{return t==STR?str:std::string();}};
static void jskip(const char*&p){while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r')p++;}
static JVal jparse(const char*&p);
static std::string jstr(const char*&p){std::string o;p++;while(*p&&*p!='"'){if(*p=='\\'){p++;switch(*p){case 'n':o+='\n';break;case 't':o+='\t';break;case 'r':o+='\r';break;case '"':o+='"';break;case '\\':o+='\\';break;case '/':o+='/';break;case 'u':{p++;int c=0;for(int i=0;i<4&&*p;i++){char h=*p++;c=c*16+(h<='9'?h-'0':(h|32)-'a'+10);}p--;if(c<128)o+=(char)c;else if(c<2048){o+=(char)(0xC0|(c>>6));o+=(char)(0x80|(c&0x3f));}else{o+=(char)(0xE0|(c>>12));o+=(char)(0x80|((c>>6)&0x3f));o+=(char)(0x80|(c&0x3f));}break;}default:o+=*p;}p++;}else o+=*p++;}if(*p=='"')p++;return o;}
static JVal jparse(const char*&p){jskip(p);JVal v;if(*p=='{'){v.t=JVal::OBJ;p++;jskip(p);if(*p=='}'){p++;return v;}while(*p){jskip(p);std::string k=jstr(p);jskip(p);if(*p==':')p++;v.obj[k]=jparse(p);jskip(p);if(*p==','){p++;continue;}if(*p=='}'){p++;break;}break;}}else if(*p=='['){v.t=JVal::ARR;p++;jskip(p);if(*p==']'){p++;return v;}while(*p){v.arr.push_back(jparse(p));jskip(p);if(*p==','){p++;continue;}if(*p==']'){p++;break;}break;}}else if(*p=='"'){v.t=JVal::STR;v.str=jstr(p);}else if(*p=='t'){v.t=JVal::BOOLV;v.b=true;p+=4;}else if(*p=='f'){v.t=JVal::BOOLV;v.b=false;p+=5;}else if(*p=='n'){v.t=JVal::NUL;p+=4;}else{v.t=JVal::NUM;char*e=nullptr;v.num=strtod(p,&e);p=e?e:p+1;}return v;}

// ===================== Константы протокола =====================
static const int CMD_IOT=939722776,CMD_MEDIA=939722784,CMD_NOTIFY=939722786;
static const int M_LANPASS=196870,M_RECLIST=197152,M_REPLAY=197154,M_ACTION=197384;
static const int M_GETPROP=197376,M_SETPROP=197378;
static const long DAID_NET=(4<<16)|512;
static const long DPID_NET_MODE=(4<<16)|256|1,DPID_NET_SIGNAL=(4<<16)|256|2,DPID_NET_SSID=(4<<16)|256|4; // 262401: 8=кабель, 2=Wi-Fi; 262404: SSID Wi-Fi
static const long DPID_TIMEZONE=(3<<16)|256|0; // 196864: пояс камеры, часы*100+минуты (0 = UTC); запись не поддерживается (1114)
static const long DPID_RECMODE=(2<<16)|256|3; // 131331: режим записи (1=постоянно,2=движение,3=оба)
static const long DPID_ALARM_MAIN=(10<<16)|256|0,DPID_ALARM_MT=(10<<16)|256|4,DPID_ALARM_TIMER=(10<<16)|256|5;
static const long DPID_ONVIF=(15<<16)|256|0; // 983296: ONVIF/RTSP (порт 554, rtsp://admin:<пароль>@ip:554/live/ch00_0)
static const long DPID_RTSP_AUDIO=(15<<16)|256|1; // 983297: звук в RTSP
static const long DPID_LIGHT=(5<<16)|256|0; // 327936: белая подсветка: 0=авто (заводское), 1=включена, 2=выключена
static int PORT=8089;            // управляющий порт камеры: поле «Port» в окне (ini [camera] port), по умолчанию 8089
static const char*AP_IP="192.168.1.1";
static const u8 HK[32]={54,58,229,40,22,56,207,132,150,154,99,78,159,150,106,152,181,115,209,255,233,55,178,119,209,241,214,43,56,116,138,229};

// ===================== Сокет / пакеты =====================
static SOCKET connectTo(const char*ip,int port){struct addrinfo hints{},*res=nullptr;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;char ps[16];sprintf(ps,"%d",port);if(getaddrinfo(ip,ps,&hints,&res)!=0)return INVALID_SOCKET;SOCKET s=socket(res->ai_family,res->ai_socktype,res->ai_protocol);if(s!=INVALID_SOCKET){DWORD to=8000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));if(connect(s,res->ai_addr,(int)res->ai_addrlen)!=0){closesocket(s);s=INVALID_SOCKET;}}freeaddrinfo(res);return s;}
static bool recvExact(SOCKET s,u8*b,size_t n){size_t g=0;while(g<n){int r=recv(s,(char*)b+g,(int)(n-g),0);if(r<=0)return false;g+=r;}return true;}
static void sendAll(SOCKET s,const u8*d,size_t n){size_t x=0;while(x<n){int r=send(s,(const char*)d+x,(int)(n-x),0);if(r<=0)break;x+=r;}}
static void le32(u8*p,u32 v){p[0]=v&0xff;p[1]=(v>>8)&0xff;p[2]=(v>>16)&0xff;p[3]=(v>>24)&0xff;}
static u32 rd32(const u8*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((u32)p[3]<<24);}
static Bytes buildPacket(int method,const std::string&params,const u8 key[32],u8 b2,u8 b3){static u32 id=0;randBytes((u8*)&id,4);id&=0x7fffffff;char head[256];int n=sprintf(head,"{\"id\":%u,\"method_id\":%d,\"chn\":1,\"ts\":%lld,\"params\":",id,method,(long long)time(nullptr));std::string js(head,head+n);js+=params;js+="}";Bytes pt(js.begin(),js.end());pt=pkcs7pad(pt);Bytes enc=aesCbc(true,key,key+16,pt.data(),pt.size());Bytes pkt(16+enc.size(),0);le32(&pkt[0],(u32)CMD_IOT);pkt[4]=1;pkt[5]=2;pkt[6]=b2;pkt[7]=b3;le32(&pkt[12],(u32)enc.size());memcpy(&pkt[16],enc.data(),enc.size());return pkt;}
struct Pkt{int cmd=0;u8 secure=0;Bytes body;std::string json;};
static bool readPacket(SOCKET s,const u8 key[32],Pkt&o){u8 h[16];if(!recvExact(s,h,16))return false;o.cmd=(int)rd32(h);o.secure=h[5];u32 ds=rd32(h+12);o.body.resize(ds);if(ds&&!recvExact(s,o.body.data(),ds))return false;if((o.cmd==CMD_IOT||o.cmd==CMD_NOTIFY)&&ds){Bytes d=aesCbc(false,key,key+16,o.body.data(),o.body.size());d=pkcs7unpad(d);o.json.assign(d.begin(),d.end());}return true;}
// Часовой пояс ПК в формате камеры: часы*100 + минуты (UTC+3 -> 300, UTC-5:30 -> -530), как DatetimeUtils.getCustomTimeZone2 в приложении.
static int tzVal(){TIME_ZONE_INFORMATION t;DWORD r=GetTimeZoneInformation(&t);int bias=-(t.Bias+(r==TIME_ZONE_ID_DAYLIGHT?t.DaylightBias:0));int a=abs(bias);return (bias<0?-1:1)*(a/60*100+a%60);}

// ===================== Протокол =====================
struct Session{SOCKET s=INVALID_SOCKET;u8 key[32]={0};int sid=0;};
static bool lanLogin(Session&ss,const char*pw){u8 seed[32];const char*al="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";u8 r[32];randBytes(r,32);for(int i=0;i<32;i++)seed[i]=al[r[i]%62];u8 pub[32];crypto_scalarmult_base(pub,seed);u8 magic;randBytes(&magic,1);u8 px[32];for(int i=0;i<32;i++)px[i]=pub[i]^magic;std::string cKM=b64enc(px,32);Bytes cat(px,px+32);for(const char*p=pw;*p;p++)cat.push_back((u8)*p);Bytes dg=sha256(cat.data(),cat.size());std::string cS=b64enc(dg.data(),32);char params[512];sprintf(params,"{\"act\":1,\"verify\":{\"cKM\":\"%s\",\"cS\":\"%s\",\"tz\":%d,\"ts\":%lld}}",cKM.c_str(),cS.c_str(),tzVal(),(long long)time(nullptr));Bytes pkt=buildPacket(M_LANPASS,params,HK,0,magic);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(!readPacket(ss.s,HK,rp))return false;if(rp.cmd!=CMD_IOT||rp.json.empty())return false;const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*data=j.get("data");const JVal*ver=data?data->get("verify"):nullptr;if(!ver||!ver->get("dK"))return false;Bytes dK=b64dec(ver->get("dK")->s());if(dK.size()<32)return false;crypto_scalarmult(ss.key,seed,dK.data());ss.sid=ver->get("sid")?(int)ver->get("sid")->n():0;return true;}
struct Seg{long long startMs;double durS;int type;};
static bool listRecordings(Session&ss,std::vector<Seg>&out){long long now=(long long)time(nullptr)*1000;long long st=now-(long long)3650*24*3600*1000,en=now;char params[160];sprintf(params,"{\"filter\":15,\"mode\":2,\"start\":%lld,\"end\":%lld}",st,en);Bytes pkt=buildPacket(M_RECLIST,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());for(;;){Pkt rp;if(!readPacket(ss.s,ss.key,rp))break;if(rp.json.empty())break;const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*data=j.get("data");if(!data)break;const JVal*lst=data->get("list");if(lst&&lst->t==JVal::ARR){for(const JVal&it:lst->arr){long long s=(long long)(it.get("s")?it.get("s")->n():0);double d=(it.get("d")?it.get("d")->n():0)/1000.0;int t=it.get("t")?(int)it.get("t")->n():0;out.push_back({st+s,d,t});}}const JVal*fl=data->get("flag");if(!fl||fl->n()==0)break;}return true;}
// mode 1 — камера в режиме точки доступа (первая настройка), mode 2 — камера уже в сети (смена Wi-Fi).
static bool provision(Session&ss,const char*ssid,const char*pw,int mode){std::string sb=b64enc((const u8*)ssid,strlen(ssid)),pb=b64enc((const u8*)pw,strlen(pw));char params[512];sprintf(params,"{\"daid\":%ld,\"in\":{\"mode\":%d,\"ssid\":\"%s\",\"pwd\":\"%s\"}}",DAID_NET,mode,sb.c_str(),pb.c_str());Bytes pkt=buildPacket(M_ACTION,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(readPacket(ss.s,ss.key,rp)&&!rp.json.empty()){const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*res=j.get("result");int code=res&&res->get("code")?(int)res->get("code")->n():1000;if(code!=1000&&code!=0)return false;}return true;}
// Режим записи: читать/писать через свойства (dpid). mode: 1=постоянно,2=движение,3=оба.
// Запись по движению идёт, только если включена тревога (ALARM_MAIN) и детектор движения с расписанием.
static int getProp(Session&ss,long dpid){char params[48];sprintf(params,"{\"dplist\":[%ld]}",dpid);Bytes pkt=buildPacket(M_GETPROP,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(!readPacket(ss.s,ss.key,rp)||rp.json.empty())return -1;const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*data=j.get("data");const JVal*dl=data?data->get("dplist_result"):nullptr;if(dl&&dl->t==JVal::ARR&&!dl->arr.empty()){const JVal*val=dl->arr[0].get("value");if(val)return val->t==JVal::BOOLV?(int)val->b:(int)val->n();}return -1;}
static int getRecordMode(Session&ss){return getProp(ss,DPID_RECMODE);}
static std::string getPropStr(Session&ss,long dpid){char params[48];sprintf(params,"{\"dplist\":[%ld]}",dpid);Bytes pkt=buildPacket(M_GETPROP,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(!readPacket(ss.s,ss.key,rp)||rp.json.empty())return "";const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*data=j.get("data");const JVal*dl=data?data->get("dplist_result"):nullptr;if(dl&&dl->t==JVal::ARR&&!dl->arr.empty()){const JVal*val=dl->arr[0].get("value");if(val&&val->t==JVal::STR)return val->s();}return "";}
static bool setProps(Session&ss,const std::string&dplist){std::string params="{\"dplist\":["+dplist+"]}";Bytes pkt=buildPacket(M_SETPROP,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(!readPacket(ss.s,ss.key,rp)||rp.json.empty())return false;const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*res=j.get("result");int code=res&&res->get("code")?(int)res->get("code")->n():0;if(code!=1000)return false;const JVal*data=j.get("data");const JVal*dl=data?data->get("dplist_result"):nullptr;if(dl&&dl->t==JVal::ARR)for(const JVal&it:dl->arr)if(it.get("code")&&(int)it.get("code")->n()!=1000)return false;return true;}
static bool setRecordMode(Session&ss,int mode){char buf[2048];if(mode==2){std::string day="{\"cnt\":1,\"sche\":[{\"enable\":true,\"mode\":1,\"s_time\":\"0:0:0\",\"e_time\":\"23:59:59\"}]}",t;const char*D[]={"Mon","Tue","Wed","Thu","Fri","Sat","Sun"};for(int i=0;i<7;i++){t+=i?",":"";t+="\"";t+=D[i];t+="\":"+day;}sprintf(buf,"{\"dpid\":%ld,\"value\":{%s}},{\"dpid\":%ld,\"value\":true},{\"dpid\":%ld,\"value\":true},{\"dpid\":%ld,\"value\":2}",DPID_ALARM_TIMER,t.c_str(),DPID_ALARM_MT,DPID_ALARM_MAIN,DPID_RECMODE);}else sprintf(buf,"{\"dpid\":%ld,\"value\":false},{\"dpid\":%ld,\"value\":1}",DPID_ALARM_MAIN,DPID_RECMODE);return setProps(ss,buf);}

// ts — время кадра в мс (заголовок кадра, байты 10..15).
static int frameDecrypt(const u8*body,size_t len,AesEcb&ecb,const u8 iv[16],Bytes&out,long long*ts=nullptr){u8 prev[16];memcpy(prev,iv,16);auto decReg=[&](const u8*d,size_t n){for(size_t i=0;i+16<=n;i+=16){u8 pt[16];ecb.decBlock(d+i,pt);for(int k=0;k<16;k++)out.push_back(pt[k]^prev[k]);memcpy(prev,d+i,16);}};if(len<32)return 0;Bytes hdr;{u8 ph[16];memcpy(ph,iv,16);for(int i=0;i<32;i+=16){u8 pt[16];ecb.decBlock(body+i,pt);for(int k=0;k<16;k++)hdr.push_back(pt[k]^ph[k]);memcpy(ph,body+i,16);}memcpy(prev,body+16,16);}int ftype=hdr[1];if(ts)*ts=(long long)rd32(&hdr[10])|((long long)(hdr[14]|(hdr[15]<<8))<<32);u32 plen=rd32(&hdr[0x12]),elen=rd32(&hdr[0x16]),slen=rd32(&hdr[0x1a]);size_t pos=32;long long rem=(long long)len-32;auto cp=[&](size_t n){for(size_t i=0;i<n&&pos<len;i++)out.push_back(body[pos++]);};if((long long)plen<=rem){cp(plen);rem-=plen;}else{cp((size_t)rem);return ftype;}while(elen>0&&rem>=(long long)elen){decReg(body+pos,elen);pos+=elen;rem-=elen;size_t sk=(size_t)((rem<(long long)slen)?rem:slen);cp(sk);rem-=sk;}if(rem>0)cp((size_t)rem);return ftype;}

// ===================== Язык интерфейса =====================
// Все строки окна: X(id, английский, русский). По умолчанию английский; выбор — меню Language, хранится в v380gui.ini ([ui] lang).
#define STRINGS(X) \
    X(S_APPTITLE,       L"V380 — camera", L"V380 — камера") \
    X(S_MENU_LANG,      L"Language", L"Язык (Language)") \
    X(S_LBL_IP,         L"Camera IP:", L"IP камеры:") \
    X(S_LBL_PW,         L"Password:", L"Пароль:") \
    X(S_LBL_PORT,       L"Port:", L"Порт:") \
    X(S_BTN_REFRESH,    L"Refresh list", L"Обновить список") \
    X(S_BTN_PLAY,       L"Watch", L"Смотреть") \
    X(S_BTN_DL,         L"Download", L"Скачать") \
    X(S_LBL_RECMODE,    L"Recording:", L"Режим записи:") \
    X(S_REC_CONT,       L"Continuous", L"Постоянно") \
    X(S_REC_MOTION,     L"On motion", L"По движению") \
    X(S_BTN_APPLY,      L"Apply to camera", L"Применить к камере") \
    X(S_LBL_LIGHT,      L"Light:", L"Свет:") \
    X(S_LIGHT_OFF,      L"Off", L"Выключен") \
    X(S_LIGHT_ON,       L"On", L"Включён") \
    X(S_LIGHT_AUTO,     L"Auto (factory)", L"Авто (заводской)") \
    X(S_BTN_LIVE,       L"Live video", L"Живое видео") \
    X(S_LBL_WIFI,       L"Wi-Fi (2.4 GHz):", L"Wi-Fi (2.4 ГГц):") \
    X(S_BTN_WIFI,       L"Connect to Wi-Fi", L"Подключить к Wi-Fi") \
    X(S_BTN_FIND,       L"Find camera", L"Найти камеру") \
    X(S_LBL_CONN,       L"Connection:", L"Подключение:") \
    X(S_RB_CABLE,       L"Cable", L"По проводу") \
    X(S_RB_WIFI,        L"Wi-Fi", L"По Wi-Fi") \
    X(S_RB_WIFI_SSID,   L"Wi-Fi \"%s\"", L"По Wi-Fi «%s»") \
    X(S_COL_NUM,        L"#", L"№") \
    X(S_COL_DATE,       L"Date and time", L"Дата и время") \
    X(S_COL_DUR,        L"Duration", L"Длительность") \
    X(S_COL_TYPE,       L"Recording type", L"Тип записи") \
    X(S_HINT,           L"Enter the camera password (from the sticker) and IP, or press \"Find camera\", then \"Refresh list\".", \
                        L"Введите пароль камеры (с наклейки) и IP или нажмите «Найти камеру», затем «Обновить список».") \
    X(S_RM_MOTION_OFF,  L"on motion (alarm is off — not recording)", L"по движению (тревога выключена — запись не идёт)") \
    X(S_RM_MOTION,      L"on motion", L"по движению") \
    X(S_RM_BOTH,        L"continuous+motion", L"постоянно+движение") \
    X(S_RM_CONT,        L"continuous", L"постоянно") \
    X(S_NET_CABLE,      L"cable", L"кабель") \
    X(S_NET_WIFI,       L"Wi-Fi \"%s\"", L"Wi-Fi «%s»") \
    X(S_NOW_CABLE,      L"Camera now: VIA CABLE", L"Сейчас камера: ПО ПРОВОДУ") \
    X(S_NOW_WIFI_SIG,   L"Camera now: VIA Wi-Fi, signal %d%%", L"Сейчас камера: ПО Wi-Fi, сигнал %d%%") \
    X(S_NOW_WIFI,       L"Camera now: VIA Wi-Fi", L"Сейчас камера: ПО Wi-Fi") \
    X(S_NOW_UNKNOWN,    L"Camera now: ? — press \"Refresh list\"", L"Сейчас камера: ? — нажмите «Обновить список»") \
    X(S_TZ_CAM,         L"Camera time zone %s", L"Пояс камеры %s") \
    X(S_TZ_BEHIND,      L": video is behind by %d:%02d", L": видео отстаёт на %d:%02d") \
    X(S_TZ_AHEAD,       L": video is ahead by %d:%02d", L": видео спешит на %d:%02d") \
    X(S_TZ_SAME,        L" — same as PC", L" — как на ПК") \
    X(S_SEL_WIFI_CABLE, L"Wi-Fi selected, but the camera is on a cable now. Unplug the cable, wait a minute and press \"Find camera\".", \
                        L"Выбран Wi-Fi, но камера сейчас на кабеле. Отключите кабель, подождите минуту и нажмите «Найти камеру».") \
    X(S_SEL_WIFI_CABLE_MSG, L"While the cable is plugged in, the camera works only over the cable — it is not on Wi-Fi.\n\n" \
                        L"Unplug the cable from the camera, wait about a minute (it will connect to Wi-Fi and get a different IP there) " \
                        L"and press \"Find camera\".", \
                        L"Пока кабель вставлен, камера работает только по проводу — в Wi-Fi её нет.\n\n" \
                        L"Отключите кабель от камеры, подождите около минуты (она подключится к Wi-Fi и получит там другой IP) " \
                        L"и нажмите «Найти камеру».") \
    X(S_NOIP_WIFI,      L"The camera's Wi-Fi address is not known yet — press \"Find camera\".", L"Адрес камеры в Wi-Fi ещё не известен — нажмите «Найти камеру».") \
    X(S_NOIP_CABLE,     L"The camera's cable address is not known yet — press \"Find camera\".", L"Адрес камеры на проводе ещё не известен — нажмите «Найти камеру».") \
    X(S_CONN_WIFI,      L"Connection via Wi-Fi. Press \"Refresh list\".", L"Подключение по Wi-Fi. Нажмите «Обновить список».") \
    X(S_CONN_CABLE,     L"Connection via cable. Press \"Refresh list\".", L"Подключение по проводу. Нажмите «Обновить список».") \
    X(S_SEARCHING,      L"Searching for camera in %u.%u.%u.x ...", L"Поиск камеры в сети %u.%u.%u.x ...") \
    X(S_CONNECTING,     L"Connecting to camera...", L"Подключение к камере...") \
    X(S_ERR_CONNECT,    L"Could not connect to the camera. Check IP and password.", L"Не удалось подключиться к камере. Проверьте IP и пароль.") \
    X(S_ERR_RTSP_ON,    L"The camera did not enable RTSP.", L"Камера не включила RTSP.") \
    X(S_ERR_RTSP_PORT,  L"The camera did not open RTSP port 554.", L"Камера не открыла RTSP-порт 554.") \
    X(S_ERR_STREAM,     L"Video stream interrupted.", L"Видеопоток прервался.") \
    X(S_ERR_FFMPEG,     L"ffmpeg not found — it must be in PATH.", L"Не найден ffmpeg — нужен в PATH.") \
    X(S_ERR_NOREC,      L"The camera did not return the recording.", L"Камера не отдала запись.") \
    X(S_LOADING_REC,    L"Loading recording...", L"Загрузка записи...") \
    X(S_LIVE_TITLE,     L"Live video — %s", L"Живое видео — %s") \
    X(S_REC_TITLE,      L"Recording %Y-%m-%d %H:%M:%S", L"Запись %Y-%m-%d %H:%M:%S") \
    X(S_LIVE_CONNECTING,L"Live video — connecting...", L"Живое видео — подключение...") \
    X(S_UNMUTE,         L"Unmute (M)", L"Включить звук (M)") \
    X(S_MUTE,           L"Mute (M)", L"Выключить звук (M)") \
    X(S_END_OF_REC,     L"%s — end of recording", L"%s — конец записи") \
    X(S_LIVE_NOCONN,    L"Live video — no connection", L"Живое видео — нет соединения") \
    X(S_REC_ERROR,      L"Recording — error", L"Запись — ошибка") \
    X(S_DUR_SEC,        L"%.1f s", L"%.1f c") \
    X(S_TYPE_MOTION,    L"motion/alarm", L"движение/тревога") \
    X(S_TYPE_SCHED,     L"scheduled", L"по расписанию") \
    X(S_TYPE_REC,       L"recording", L"запись") \
    X(S_LIST_STATUS,    L"Recordings on SD card: %zu   •   recording mode: %s   •   network: %s", L"Записей на SD-карте: %zu   •   режим записи: %s   •   сеть: %s") \
    X(S_SELECT_REC,     L"Select a recording in the list.", L"Выберите запись в списке.") \
    X(S_FILTER_MP4,     L"MP4 video\0*.mp4\0All files\0*.*\0", L"Видео MP4\0*.mp4\0Все файлы\0*.*\0") \
    X(S_DL_CONNECTING,  L"Downloading: connecting...", L"Скачивание: подключение...") \
    X(S_LIGHT_SENDING,  L"Sending light setting to the camera...", L"Отправка настройки света в камеру...") \
    X(S_REC_SENDING,    L"Sending recording setting to the camera...", L"Отправка настройки записи в камеру...") \
    X(S_ENTER_SSID,     L"Enter the Wi-Fi network name.", L"Введите имя Wi-Fi сети.") \
    X(S_5G_WARN,        L"The camera works only with 2.4 GHz Wi-Fi, and the network name looks like 5 GHz. Send anyway?", \
                        L"Камера работает только с Wi-Fi 2.4 ГГц, а имя сети похоже на 5 ГГц. Всё равно отправить?") \
    X(S_WIFI_SENDING,   L"Sending Wi-Fi network to the camera...", L"Передаю камере Wi-Fi сеть...") \
    X(S_OPFAIL,         L"Camera not found either at the address or by searching the network. Check the password and that the camera is on the same network as the PC.", \
                        L"Камера не найдена ни по адресу, ни поиском в сети. Проверьте пароль и что камера в той же сети, что ПК.") \
    X(S_REC_DONE,       L"Done: camera recording mode — %s.", L"Готово: режим записи камеры — %s.") \
    X(S_REC_APPLIED,    L"The recording setting has been applied to the camera.", L"Настройка записи применена к камере.") \
    X(S_REC_FAIL,       L"Could not apply the recording setting.", L"Не удалось применить настройку записи.") \
    X(S_WIFI_ACCEPTED,  L"The camera accepted the network \"%s\".", L"Камера приняла сеть «%s».") \
    X(S_WIFI_ACCEPTED_MSG, L"The camera accepted the network \"%s\" and is connecting to it.\n\nOn Wi-Fi the camera will have a different IP. In a minute press \"Find camera\" — the program will find it and fill in the address.", \
                        L"Камера приняла сеть «%s» и подключается к ней.\n\nВ Wi-Fi у камеры будет другой IP. Через минуту нажмите «Найти камеру» — программа найдёт её и подставит адрес.") \
    X(S_WIFI_REJECTED,  L"The camera rejected the Wi-Fi setting.", L"Камера отклонила настройку Wi-Fi.") \
    X(S_FOUND,          L"Camera found: %s. Press \"Refresh list\".", L"Камера найдена: %s. Нажмите «Обновить список».") \
    X(S_NOT_FOUND,      L"Camera not found: no address on the local networks accepted the camera password.", L"Камера не найдена: ни один адрес в локальных сетях не принял пароль камеры.") \
    X(S_DL_PROGRESS,    L"Downloading... video frames: %d, audio: %d", L"Скачивание... кадров видео: %d, аудио: %d") \
    X(S_DL_DONE,        L"Done: %d video frames, %d audio.", L"Готово: %d видеокадров, %d аудио.") \
    X(S_DL_OPEN,        L"Recording downloaded. Open the file?", L"Запись скачана. Открыть файл?") \
    X(S_DL_NOMP4,       L"mp4 was not created (no ffmpeg in PATH) — raw .h264 and .alaw are saved next to it.", L"mp4 не собран (нет ffmpeg в PATH) — рядом сохранены сырые .h264 и .alaw.") \
    X(S_DL_FAIL,        L"Download failed (no frames or no connection).", L"Скачать не удалось (нет кадров или нет соединения).") \
    X(S_LIGHT_ON_ST,    L"Light is on.", L"Свет включён.") \
    X(S_LIGHT_OFF_ST,   L"Light is off.", L"Свет выключен.") \
    X(S_LIGHT_AUTO_ST,  L"Light: auto (factory mode).", L"Свет: авто (заводской режим).") \
    X(S_LIGHT_FAIL,     L"Could not change the light.", L"Не удалось изменить свет.")
enum Str{
#define X(id,en,ru) id,
    STRINGS(X)
#undef X
    S_COUNT};
static const wchar_t* const STR[S_COUNT][2]={
#define X(id,en,ru) {en,ru},
    STRINGS(X)
#undef X
};
static int g_lang=0;            // 0 — English, 1 — русский
static const wchar_t* T(Str s){ return STR[s][g_lang]; }
#define APPTITLE T(S_APPTITLE)

// ===================== GUI =====================
enum{IDC_IP=101,IDC_PW,IDC_REFRESH,IDC_LIST,IDC_DOWNLOAD,IDC_RECMODE,IDC_APPLYREC,IDC_LIVE,IDC_WSSID,IDC_WPW,IDC_WIFI,IDC_FIND,IDM_MUTE,IDC_PLAY,IDC_LIGHT,IDC_RBCABLE,IDC_RBWIFI,IDM_LANG_EN,IDM_LANG_RU,IDC_PORT};
static HWND g_main,g_ip,g_pw,g_btnRef,g_btnDl,g_list,g_status,g_combo,g_btnApply,g_btnLive,g_wssid,g_wpw,g_btnWifi,g_btnFind,g_btnPlay,g_light;
static HWND g_port,g_lblPort,g_lblIp,g_lblPw,g_lblRec,g_lblLight,g_lblWifi,g_lblWpw,g_lblConn;
static HMENU g_menuLang;
static HWND g_netlbl,g_tzlbl;   // над списком: в какой сети камера сейчас и её часовой пояс
static HWND g_rbCable,g_rbWifi; // выбор подключения: у каждого варианта свой запомненный IP камеры
static HFONT g_font,g_fontBold;
static std::vector<Seg> g_segs;
static volatile bool g_busy=false;
static int g_recmode=-1;        // текущий режим записи (читается при обновлении)
static int g_alarm=-1;          // главный выключатель тревоги
static int g_applyMode=0;       // режим, который применяем
static int g_netmode=-1;        // сеть камеры: 8=кабель, иначе Wi-Fi
static std::string g_netssid;
static int g_camtz=-1;          // пояс камеры (часы*100+минуты); -1 — не прочитан
static int g_sel=8;             // выбранное подключение: 8=провод, 2=Wi-Fi (как DPID_NET_MODE)
static int g_lastLink=-1;       // сеть камеры при последнем удачном подключении (из ini) — пока не обновили список
static wchar_t g_ipbuf[64], g_pwbuf[64], g_ssidbuf[64], g_wpwbuf[64];
// IP и пароль камеры запоминаются в %APPDATA%\v380gui.ini после удачного подключения.
// Порт из поля «Port»; пустое или неверное значение — стандартный 8089.
static void readPort(){ wchar_t b[16]; GetWindowTextW(g_port,b,16); int p=_wtoi(b); PORT=p>0&&p<65536?p:8089; }
static std::wstring iniPath(){ wchar_t p[MAX_PATH]; DWORD n=GetEnvironmentVariableW(L"APPDATA",p,MAX_PATH); return std::wstring(n&&n<MAX_PATH?p:L".")+L"\\v380gui.ini"; }
#define WM_LISTREADY (WM_APP+1)
#define WM_DLPROGRESS (WM_APP+2)
#define WM_DLDONE     (WM_APP+3)
#define WM_OPFAIL     (WM_APP+4)
#define WM_RECDONE    (WM_APP+5)
#define WM_LIVEMSG    (WM_APP+6)
#define WM_WIFIDONE   (WM_APP+7)
#define WM_FOUND      (WM_APP+8)
#define WM_LIGHTDONE  (WM_APP+9)
static int g_lightmode=-1;      // подсветка: 0=авто,1=вкл,2=выкл

static std::string wtoutf8(const wchar_t*w){int n=WideCharToMultiByte(CP_UTF8,0,w,-1,nullptr,0,nullptr,nullptr);std::string s(n>0?n-1:0,0);if(n>0)WideCharToMultiByte(CP_UTF8,0,w,-1,&s[0],n,nullptr,nullptr);return s;}
static void setStatus(const wchar_t*t){ if(g_status) SetWindowTextW(g_status,t); }

static std::string searchCamera(const std::string& pw);
// Уровень Wi-Fi сигнала камеры, % (DPID 262402 → {"mode":2,"signal_level":100,...}); на кабеле -1.
static int getWifiSignal(Session&ss){char params[48];sprintf(params,"{\"dplist\":[%ld]}",DPID_NET_SIGNAL);Bytes pkt=buildPacket(M_GETPROP,params,ss.key,(u8)ss.sid,0);sendAll(ss.s,pkt.data(),pkt.size());Pkt rp;if(!readPacket(ss.s,ss.key,rp)||rp.json.empty())return -1;const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*data=j.get("data");const JVal*dl=data?data->get("dplist_result"):nullptr;if(dl&&dl->t==JVal::ARR&&!dl->arr.empty()){const JVal*val=dl->arr[0].get("value");const JVal*lv=val?val->get("signal_level"):nullptr;if(lv)return (int)lv->n();}return -1;}
static int g_signal=-1;

// --- поток: обновить список ---
// Если по сохранённому адресу камера не отвечает (например, ушла с кабеля в Wi-Fi и получила там другой IP),
// программа сама ищет её в локальной сети и переходит на найденный адрес.
static unsigned __stdcall refreshThread(void*){
    g_busy=true; SetWindowTextW(g_status,T(S_CONNECTING));
    std::string ip=wtoutf8(g_ipbuf), pw=wtoutf8(g_pwbuf);
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT);
    bool ok=ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str());
    if(!ok){
        if(ss.s!=INVALID_SOCKET){ closesocket(ss.s); ss.s=INVALID_SOCKET; }
        std::string found=searchCamera(pw);
        if(!found.empty() && found!=ip){
            ss.s=connectTo(found.c_str(),PORT); ok=ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str());
            if(ok) swprintf(g_ipbuf,64,L"%hs",found.c_str());   // окно подставит новый адрес в поле IP
        }
    }
    if(ok){
        g_segs.clear(); listRecordings(ss,g_segs); g_recmode=getRecordMode(ss); g_alarm=getProp(ss,DPID_ALARM_MAIN); g_lightmode=getProp(ss,DPID_LIGHT);
        g_netmode=getProp(ss,DPID_NET_MODE); g_netssid=getPropStr(ss,DPID_NET_SSID); g_camtz=getProp(ss,DPID_TIMEZONE);
        g_signal=g_netmode==2?getWifiSignal(ss):-1;
    } else { g_netmode=-1; g_camtz=-1; g_signal=-1; }
    if(ss.s!=INVALID_SOCKET) closesocket(ss.s); WSACleanup();
    PostMessageW(g_main, ok?WM_LISTREADY:WM_OPFAIL, 0, 0);
    g_busy=false; return 0;
}

struct DlArg{int seg; wchar_t out[MAX_PATH];};
static wchar_t g_lastOut[MAX_PATH];
static bool fileExists(const char*p){return GetFileAttributesA(p)!=INVALID_FILE_ATTRIBUTES;}

// Сборка mp4 из сырых потоков через ffmpeg; без ffmpeg рядом остаются .h264 и .alaw.
static void saveMp4(const Bytes&video,const Bytes&audio,int nv,double durS,const std::string&outMp4){
    int fps=durS>0?(int)(nv/durS+0.5):15; if(fps<1)fps=1;
    std::string vt=outMp4+".h264",at=outMp4+".alaw";
    FILE*f=fopen(vt.c_str(),"wb"); if(f){fwrite(video.data(),1,video.size(),f);fclose(f);}
    if(!audio.empty()){FILE*fa=fopen(at.c_str(),"wb");if(fa){fwrite(audio.data(),1,audio.size(),fa);fclose(fa);}}
    char cmd[2048];
    if(!audio.empty()) sprintf(cmd,"ffmpeg -v error -y -r %d -i \"%s\" -f alaw -ar 16000 -ac 1 -i \"%s\" -map 0:v:0 -map 1:a:0 -c:v copy -c:a aac \"%s\"",fps,vt.c_str(),at.c_str(),outMp4.c_str());
    else sprintf(cmd,"ffmpeg -v error -y -r %d -i \"%s\" -c copy \"%s\"",fps,vt.c_str(),outMp4.c_str());
    STARTUPINFOA si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi{}; std::string cl="cmd /c "; cl+=cmd;
    if(CreateProcessA(nullptr,(LPSTR)cl.c_str(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)){
        WaitForSingleObject(pi.hProcess,INFINITE); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    if(fileExists(outMp4.c_str())){ remove(vt.c_str()); if(!audio.empty())remove(at.c_str()); }
}

// --- поток: скачать запись ---
static unsigned __stdcall downloadThread(void* a){
    DlArg* arg=(DlArg*)a; g_busy=true;
    std::string ip=wtoutf8(g_ipbuf), pw=wtoutf8(g_pwbuf), outMp4=wtoutf8(arg->out);
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT); bool ok=false; int nv=0,na=0;
    if(ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str()) && arg->seg<(int)g_segs.size()){
        Seg seg=g_segs[arg->seg]; AesEcb ecb; ecb.init(ss.key);
        auto req=[&](const std::string&p){Bytes pk=buildPacket(M_REPLAY,p,ss.key,(u8)ss.sid,0);sendAll(ss.s,pk.data(),pk.size());};
        char p0[256]; sprintf(p0,"{\"pts\":%lld,\"sts\":%lld,\"rtype\":%d,\"time_id\":1,\"vsspec\":0,\"frames\":1000,\"video\":1,\"audio\":1}",seg.startMs,seg.startMs,seg.type);
        req(p0);
        Bytes video,audio; bool done=false; double limit=seg.durS+15; DWORD t0=GetTickCount();
        while(!done && (GetTickCount()-t0)/1000.0<limit){
            Pkt rp; if(!readPacket(ss.s,ss.key,rp))break;
            if(rp.cmd==CMD_MEDIA){ Bytes pl; int ft=frameDecrypt(rp.body.data(),rp.body.size(),ecb,ss.key+16,pl);
                if(ft==1||ft==2){video.insert(video.end(),pl.begin(),pl.end());nv++;}
                else if(ft==4){audio.insert(audio.end(),pl.begin(),pl.end());na++;}
                if(nv%25==0) PostMessageW(g_main,WM_DLPROGRESS,(WPARAM)nv,(LPARAM)na);
            } else if(rp.cmd==CMD_NOTIFY && !rp.json.empty()){
                const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*par=j.get("params");int iid=par&&par->get("info_id")?(int)par->get("info_id")->n():0;
                if(iid==4)req("{\"time_id\":1,\"frames\":1000}"); else if(iid==3)done=true;
            }
        }
        if(nv>0){ saveMp4(video,audio,nv,seg.durS,outMp4); ok=true; }
    }
    if(ss.s!=INVALID_SOCKET)closesocket(ss.s); WSACleanup();
    wcscpy_s(g_lastOut,arg->out);
    PostMessageW(g_main,WM_DLDONE,(WPARAM)(ok?1:0),(LPARAM)((nv<<16)|(na&0xffff)));
    delete arg; g_busy=false; return 0;
}

// --- поток: применить режим записи ---
static unsigned __stdcall applyRecThread(void*){
    g_busy=true; std::string ip=wtoutf8(g_ipbuf),pw=wtoutf8(g_pwbuf);
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT); bool ok=false;
    if(ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str())){ ok=setRecordMode(ss,g_applyMode); if(ok){g_recmode=getRecordMode(ss); g_alarm=getProp(ss,DPID_ALARM_MAIN);} }
    if(ss.s!=INVALID_SOCKET)closesocket(ss.s); WSACleanup();
    PostMessageW(g_main,WM_RECDONE,(WPARAM)(ok?1:0),0); g_busy=false; return 0;
}
// --- поток: подсветка ---
static unsigned __stdcall lightThread(void* a){
    g_busy=true; int mode=(int)(INT_PTR)a; std::string ip=wtoutf8(g_ipbuf),pw=wtoutf8(g_pwbuf);
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT); bool ok=false;
    if(ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str())){
        char b[48]; sprintf(b,"{\"dpid\":%ld,\"value\":%d}",DPID_LIGHT,mode);
        ok=setProps(ss,b); g_lightmode=getProp(ss,DPID_LIGHT);
    }
    if(ss.s!=INVALID_SOCKET)closesocket(ss.s); WSACleanup();
    PostMessageW(g_main,WM_LIGHTDONE,(WPARAM)(ok?1:0),0); g_busy=false; return 0;
}
// combo «Свет» <-> значение (0:Выключен=2, 1:Включён=1, 2:Авто=0)
static int comboToLight(int idx){ return idx==0?2:(idx==1?1:0); }
static int lightToCombo(int v){ return v==2?0:(v==1?1:2); }
// combo index <-> значение режима (0:Постоянно=1, 1:По движению=2)
static int comboToMode(int idx){ return idx==1?2:1; }
static int modeToCombo(int mode){ return mode==2?1:0; }
static const wchar_t* recModeName(){ return g_recmode==2?(g_alarm==0?T(S_RM_MOTION_OFF):T(S_RM_MOTION)):(g_recmode==3?T(S_RM_BOTH):(g_recmode==1?T(S_RM_CONT):L"?")); }
static std::wstring ssidW(){
    int n=MultiByteToWideChar(CP_UTF8,0,g_netssid.c_str(),-1,nullptr,0); std::wstring w(n>0?n-1:0,0);
    if(n>1) MultiByteToWideChar(CP_UTF8,0,g_netssid.c_str(),-1,&w[0],n);
    return w;
}
static std::wstring netName(){
    if(g_netmode==8) return T(S_NET_CABLE);
    if(g_netmode<=0) return L"?";
    wchar_t b[160]; swprintf(b,160,T(S_NET_WIFI),ssidW().c_str()); return b;
}
static std::wstring tzName(int v){ wchar_t b[16]; if(v%100) swprintf(b,16,L"UTC%+d:%02d",v/100,abs(v%100)); else swprintf(b,16,L"UTC%+d",v/100); return b; }
static int tzMinutes(int v){ return v/100*60+v%100; }
// Строка над списком: как камера подключена к сети и совпадает ли её часовой пояс с ПК.
static void updateInfo(){
    wchar_t net[96];
    if(g_netmode==8) wcscpy_s(net,T(S_NOW_CABLE));
    else if(g_netmode>0 && g_signal>=0) swprintf(net,96,T(S_NOW_WIFI_SIG),g_signal);
    else if(g_netmode>0) wcscpy_s(net,T(S_NOW_WIFI));
    else wcscpy_s(net,T(S_NOW_UNKNOWN));
    SetWindowTextW(g_netlbl,net);
    std::wstring tz;
    if(g_camtz!=-1){
        int d=tzMinutes(tzVal())-tzMinutes(g_camtz);
        wchar_t b[96]; swprintf(b,96,T(S_TZ_CAM),tzName(g_camtz).c_str()); tz=b;
        if(d){ swprintf(b,96,T(d>0?S_TZ_BEHIND:S_TZ_AHEAD),abs(d)/60,abs(d)%60); tz+=b; }
        else tz+=T(S_TZ_SAME);
    }
    SetWindowTextW(g_tzlbl,tz.c_str());
    InvalidateRect(g_netlbl,nullptr,TRUE); InvalidateRect(g_tzlbl,nullptr,TRUE);
}

// --- выбор подключения: провод / Wi-Fi ---
// Камера сама выбирает интерфейс: пока вставлен кабель, она работает только по нему, без кабеля — по Wi-Fi,
// и в каждой сети у неё свой IP. Поэтому выбор здесь — какой из двух запомненных адресов использовать.
static int curLink(){ return g_netmode==8||g_netmode==2?g_netmode:g_lastLink; }
static const wchar_t* profKey(int sel){ return sel==2?L"ip_wifi":L"ip_cable"; }
static void loadProfileIp(int sel){
    wchar_t b[64]; GetPrivateProfileStringW(L"camera",profKey(sel),L"",b,64,iniPath().c_str());
    if(!b[0] && sel==8) GetPrivateProfileStringW(L"camera",L"ip",L"",b,64,iniPath().c_str()); // ini старых версий
    SetWindowTextW(g_ip,b);
}
static void saveProfileIp(int sel,const wchar_t* ip){ if(ip[0]) WritePrivateProfileStringW(L"camera",profKey(sel),ip,iniPath().c_str()); }
// Нет кабеля (камера в Wi-Fi) — вариант «По проводу» недоступен, остаётся только Wi-Fi.
static void syncRadios(){
    bool noCable=curLink()==2;
    if(noCable) g_sel=2;
    EnableWindow(g_rbCable,!noCable);
    wchar_t wt[160]; if(g_netssid.empty()) wcscpy_s(wt,T(S_RB_WIFI)); else swprintf(wt,160,T(S_RB_WIFI_SSID),ssidW().c_str());
    SetWindowTextW(g_rbWifi,wt);
    SendMessageW(g_rbCable,BM_SETCHECK,g_sel==8?BST_CHECKED:BST_UNCHECKED,0);
    SendMessageW(g_rbWifi,BM_SETCHECK,g_sel==2?BST_CHECKED:BST_UNCHECKED,0);
}
static void selectConn(int sel){
    if(sel==8 && curLink()==2){ syncRadios(); return; }   // кабеля нет — «По проводу» недоступен
    if(sel==g_sel) return;
    wchar_t ip[64]; GetWindowTextW(g_ip,ip,64); saveProfileIp(g_sel,ip);
    g_sel=sel; WritePrivateProfileStringW(L"camera",L"conn",sel==2?L"2":L"8",iniPath().c_str());
    loadProfileIp(sel); syncRadios();
    GetWindowTextW(g_ip,ip,64);
    if(sel==2 && curLink()==8){
        setStatus(T(S_SEL_WIFI_CABLE));
        MessageBoxW(g_main,T(S_SEL_WIFI_CABLE_MSG),APPTITLE,MB_OK|MB_ICONINFORMATION);
    } else if(!ip[0]) setStatus(T(sel==2?S_NOIP_WIFI:S_NOIP_CABLE));
    else setStatus(T(sel==2?S_CONN_WIFI:S_CONN_CABLE));
}

// --- поток: передать камере Wi-Fi сеть (камера уже в сети) ---
static unsigned __stdcall wifiThread(void*){
    g_busy=true; std::string ip=wtoutf8(g_ipbuf),pw=wtoutf8(g_pwbuf),ssid=wtoutf8(g_ssidbuf),wpw=wtoutf8(g_wpwbuf);
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT); int res=0;
    if(ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str())) res=provision(ss,ssid.c_str(),wpw.c_str(),2)?1:2;
    if(ss.s!=INVALID_SOCKET)closesocket(ss.s); WSACleanup();
    PostMessageW(g_main,WM_WIFIDONE,(WPARAM)res,0); g_busy=false; return 0;
}

// --- найти камеру — перебор адресов локальных сетей /24 по порту 8089 и проверка пароля ---
// Возвращает IP камеры или пустую строку. Winsock должен быть уже инициализирован.
static std::string searchCamera(const std::string& pw){
    std::string found;
    std::vector<u32> own,nets;
    char hn[256]; struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_INET;
    if(gethostname(hn,sizeof(hn))==0 && getaddrinfo(hn,nullptr,&hints,&res)==0){
        for(addrinfo*a=res;a;a=a->ai_next){
            u32 v=ntohl(((sockaddr_in*)a->ai_addr)->sin_addr.s_addr);
            if((v>>24)==127 || (v>>16)==0xA9FE) continue;
            own.push_back(v); u32 n=v&0xFFFFFF00; bool dup=false; for(u32 x:nets) dup|=x==n; if(!dup) nets.push_back(n);
        }
        freeaddrinfo(res);
    }
    for(size_t k=0;k<nets.size() && found.empty();k++){
        wchar_t st[96]; swprintf(st,96,T(S_SEARCHING),nets[k]>>24,(nets[k]>>16)&255,(nets[k]>>8)&255); setStatus(st);
        std::vector<u32> open;
        for(int b=1;b<255;b+=60){
            std::vector<std::pair<SOCKET,u32>> pend;
            for(int h=b;h<b+60 && h<255;h++){
                u32 v=nets[k]|h; bool me=false; for(u32 x:own) me|=x==v; if(me) continue;
                SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
                sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(PORT); sa.sin_addr.s_addr=htonl(v);
                connect(s,(sockaddr*)&sa,sizeof(sa)); pend.push_back({s,v});
            }
            DWORD end=GetTickCount()+700;
            while(!pend.empty() && GetTickCount()<end){
                fd_set wf,ef; FD_ZERO(&wf); FD_ZERO(&ef); for(auto&p:pend){ FD_SET(p.first,&wf); FD_SET(p.first,&ef); }
                DWORD left=end-GetTickCount(); timeval tv{0,(long)(left>700?0:left)*1000};
                if(select(0,nullptr,&wf,&ef,&tv)<=0) break;
                for(size_t i=0;i<pend.size();){
                    if(FD_ISSET(pend[i].first,&wf)) open.push_back(pend[i].second);
                    if(FD_ISSET(pend[i].first,&wf)||FD_ISSET(pend[i].first,&ef)){ closesocket(pend[i].first); pend.erase(pend.begin()+i); } else i++;
                }
            }
            for(auto&p:pend) closesocket(p.first);
        }
        for(u32 v:open){
            char ip[16]; sprintf(ip,"%u.%u.%u.%u",v>>24,(v>>16)&255,(v>>8)&255,v&255);
            Session ss; ss.s=connectTo(ip,PORT); bool ok=ss.s!=INVALID_SOCKET && lanLogin(ss,pw.c_str());
            if(ss.s!=INVALID_SOCKET) closesocket(ss.s);
            if(ok){ found=ip; break; }
        }
    }
    return found;
}
static wchar_t g_foundIp[64];
static unsigned __stdcall findThread(void*){
    g_busy=true; std::string pw=wtoutf8(g_pwbuf); g_foundIp[0]=0;
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    std::string ip=searchCamera(pw); if(!ip.empty()) swprintf(g_foundIp,64,L"%hs",ip.c_str());
    WSACleanup();
    PostMessageW(g_main,WM_FOUND,0,0); g_busy=false; return 0;
}

// --- живое видео: RTSP камеры -> ffmpeg -> кадры BGR -> окно ---
static const int LIVE_W=1280,LIVE_H=720;
static HWND g_live;
static HANDLE g_liveThr=nullptr,g_liveProc=nullptr,g_audioProc=nullptr;
static volatile bool g_liveStop=false,g_mute=false;
static CRITICAL_SECTION g_liveCs;
static Bytes g_liveFrame;
static const wchar_t* g_liveText=L"";

static bool waitPort(const char*ip,int port,int sec){
    for(int i=0;i<sec && !g_liveStop;i++){ SOCKET s=connectTo(ip,port); if(s!=INVALID_SOCKET){ closesocket(s); return true; } Sleep(1000); }
    return false;
}

// Запускает ffmpeg со stdout в pipe; *slot — куда положить процесс, чтобы stopLive мог его убить.
// in != nullptr — stdin тоже pipe, в *in возвращается конец для записи.
static HANDLE runFfmpeg(char*cmd,HANDLE*slot,HANDLE&proc,HANDLE*in=nullptr){
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE}; HANDLE rd=nullptr,wr=nullptr,ird=nullptr;
    if(!CreatePipe(&rd,&wr,&sa,1<<20)) return nullptr;
    SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
    if(in){ if(!CreatePipe(&ird,in,&sa,1<<20)){ CloseHandle(rd); CloseHandle(wr); return nullptr; } SetHandleInformation(*in,HANDLE_FLAG_INHERIT,0); }
    HANDLE nul=CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr);
    STARTUPINFOA si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES; si.hStdInput=in?ird:nul; si.hStdOutput=wr; si.hStdError=nul;
    PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessA(nullptr,cmd,nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi);
    CloseHandle(wr); if(ird) CloseHandle(ird); if(nul!=INVALID_HANDLE_VALUE) CloseHandle(nul);
    if(!ok){ CloseHandle(rd); if(in) CloseHandle(*in); return nullptr; }
    CloseHandle(pi.hThread); proc=pi.hProcess;
    EnterCriticalSection(&g_liveCs); *slot=proc; LeaveCriticalSection(&g_liveCs);
    if(g_liveStop) TerminateProcess(proc,0);
    return rd;
}
static void endFfmpeg(HANDLE rd,HANDLE*slot,HANDLE proc){
    EnterCriticalSection(&g_liveCs); *slot=nullptr; LeaveCriticalSection(&g_liveCs);
    TerminateProcess(proc,0); CloseHandle(proc); CloseHandle(rd);
}
static bool readFull(HANDLE h,u8*p,size_t n){
    size_t g=0; DWORD got=0;
    while(g<n && ReadFile(h,p+g,(DWORD)(n-g),&got,nullptr) && got) g+=got;
    return g==n;
}

// Звук: отдельная RTSP-сессия только с аудио (G.711 A-law 8 кГц) -> PCM 16 кГц -> waveOut.
static unsigned __stdcall liveAudioThread(void*){
    std::string ip=wtoutf8(g_ipbuf), pw=wtoutf8(g_pwbuf);
    char cmd[512];
    sprintf(cmd,"ffmpeg -nostdin -v error -rtsp_transport tcp -allowed_media_types audio -fflags nobuffer -i \"rtsp://admin:%s@%s:554/live/ch00_0\" -vn -ar 16000 -ac 1 -f s16le -",pw.c_str(),ip.c_str());
    HANDLE proc=nullptr, rd=runFfmpeg(cmd,&g_audioProc,proc);
    if(!rd) return 0;
    WAVEFORMATEX wf{WAVE_FORMAT_PCM,1,16000,32000,2,16,0}; HWAVEOUT wo=nullptr;
    if(waveOutOpen(&wo,WAVE_MAPPER,&wf,0,0,CALLBACK_NULL)==MMSYSERR_NOERROR){
        const int NB=5,BS=3200;        // 5 буферов по 100 мс: очередь не больше полсекунды
        Bytes mem((size_t)NB*BS), chunk(BS); WAVEHDR hd[NB]={};
        for(int i=0;i<NB;i++){ hd[i].lpData=(LPSTR)&mem[(size_t)i*BS]; hd[i].dwBufferLength=BS; waveOutPrepareHeader(wo,&hd[i],sizeof(WAVEHDR)); }
        while(readFull(rd,chunk.data(),BS)){
            if(g_mute) continue;
            for(int i=0;i<NB;i++) if(!(hd[i].dwFlags&WHDR_INQUEUE)){
                memcpy(hd[i].lpData,chunk.data(),BS); waveOutWrite(wo,&hd[i],sizeof(WAVEHDR)); break;
            }
        }
        waveOutReset(wo);
        for(int i=0;i<NB;i++) waveOutUnprepareHeader(wo,&hd[i],sizeof(WAVEHDR));
        waveOutClose(wo);
    }
    endFfmpeg(rd,&g_audioProc,proc);
    return 0;
}

static unsigned __stdcall liveThread(void* a){
    HWND hw=(HWND)a;
    std::string ip=wtoutf8(g_ipbuf), pw=wtoutf8(g_pwbuf);
    const wchar_t* err=nullptr;
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT);
    if(ss.s==INVALID_SOCKET || !lanLogin(ss,pw.c_str())) err=T(S_ERR_CONNECT);
    else if(getProp(ss,DPID_ONVIF)!=1 || getProp(ss,DPID_RTSP_AUDIO)!=1){
        char b[96]; sprintf(b,"{\"dpid\":%ld,\"value\":true},{\"dpid\":%ld,\"value\":true}",DPID_ONVIF,DPID_RTSP_AUDIO);
        if(!setProps(ss,b)) err=T(S_ERR_RTSP_ON);
        else Sleep(3000);
    }
    if(ss.s!=INVALID_SOCKET) closesocket(ss.s);
    if(!err && !waitPort(ip.c_str(),554,15)) err=T(S_ERR_RTSP_PORT);
    WSACleanup();
    if(!err && !g_liveStop){
        HANDLE at=(HANDLE)_beginthreadex(nullptr,0,liveAudioThread,nullptr,0,nullptr);
        char cmd[512];
        sprintf(cmd,"ffmpeg -nostdin -v error -rtsp_transport tcp -allowed_media_types video -fflags nobuffer -flags low_delay -i \"rtsp://admin:%s@%s:554/live/ch00_0\" -an -vf scale=%d:%d -pix_fmt bgr24 -f rawvideo -",pw.c_str(),ip.c_str(),LIVE_W,LIVE_H);
        HANDLE proc=nullptr, rd=runFfmpeg(cmd,&g_liveProc,proc);
        if(rd){
            Bytes buf((size_t)LIVE_W*LIVE_H*3); bool first=true;
            while(readFull(rd,buf.data(),buf.size())){
                EnterCriticalSection(&g_liveCs); g_liveFrame=buf; LeaveCriticalSection(&g_liveCs);
                if(first){ PostMessageW(hw,WM_LIVEMSG,1,0); first=false; }
                InvalidateRect(hw,nullptr,FALSE);
            }
            endFfmpeg(rd,&g_liveProc,proc);
            err=T(S_ERR_STREAM);
        } else err=T(S_ERR_FFMPEG);
        EnterCriticalSection(&g_liveCs); if(g_audioProc) TerminateProcess(g_audioProc,0); LeaveCriticalSection(&g_liveCs);
        if(at){ WaitForSingleObject(at,INFINITE); CloseHandle(at); }
    }
    if(!g_liveStop) PostMessageW(hw,WM_LIVEMSG,0,(LPARAM)err);
    return 0;
}

// --- просмотр записи во время загрузки ---
// Камера отдаёт кадры пачками быстрее реального времени; они копятся в очередях и выдаются
// по меткам времени: видео — в ffmpeg (декодирование в BGR для окна), звук — сразу в waveOut.
struct PlayFrame{long long ts; Bytes data;};
static int g_playSeg=-1;                    // запись в окне просмотра; -1 — живое видео
static SOCKET g_playSock=INVALID_SOCKET;
static wchar_t g_playOut[MAX_PATH], g_liveTitle[128];

static short alaw2pcm(u8 a){ a^=0x55; int t=(a&15)<<4, seg=(a&0x70)>>4; t+=seg?0x108:8; if(seg>1) t<<=seg-1; return (short)((a&0x80)?t:-t); }

static unsigned __stdcall playThread(void* a){
    HWND hw=(HWND)a; Seg seg=g_segs[g_playSeg];
    std::string ip=wtoutf8(g_ipbuf), pw=wtoutf8(g_pwbuf), outMp4=wtoutf8(g_playOut);
    const wchar_t* err=nullptr;
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    Session ss; ss.s=connectTo(ip.c_str(),PORT);
    if(ss.s==INVALID_SOCKET || !lanLogin(ss,pw.c_str())) err=T(S_ERR_CONNECT);
    else{
        EnterCriticalSection(&g_liveCs); g_playSock=ss.s; LeaveCriticalSection(&g_liveCs);
        char cmd[512];
        sprintf(cmd,"ffmpeg -v error -threads 1 -fflags nobuffer -flags low_delay -probesize 32 -analyzeduration 0 -f h264 -i - -vf scale=%d:%d -pix_fmt bgr24 -fps_mode passthrough -f rawvideo -",LIVE_W,LIVE_H);
        HANDLE in=nullptr, proc=nullptr, rd=runFfmpeg(cmd,&g_liveProc,proc,&in);
        if(!rd) err=T(S_ERR_FFMPEG);
        else{
            std::mutex mx; std::deque<PlayFrame> vq,aq; bool netDone=false;
            std::thread show([&]{
                Bytes buf((size_t)LIVE_W*LIVE_H*3); bool first=true;
                while(readFull(rd,buf.data(),buf.size())){
                    EnterCriticalSection(&g_liveCs); g_liveFrame=buf; LeaveCriticalSection(&g_liveCs);
                    if(first){ PostMessageW(hw,WM_LIVEMSG,1,0); first=false; }
                    InvalidateRect(hw,nullptr,FALSE);
                }
            });
            std::thread feed([&]{
                const int LEAD=300,NB=32,BS=1920;      // звук уходит в waveOut на 300 мс раньше, очередь начинается с такой же тишины
                WAVEFORMATEX wf{WAVE_FORMAT_PCM,1,16000,32000,2,16,0}; HWAVEOUT wo=nullptr;
                if(waveOutOpen(&wo,WAVE_MAPPER,&wf,0,0,CALLBACK_NULL)!=MMSYSERR_NOERROR) wo=nullptr;
                Bytes mem((size_t)(NB+1)*BS*5); WAVEHDR hd[NB+1]={};
                for(int i=0;i<=NB;i++){ hd[i].lpData=(LPSTR)&mem[(size_t)i*BS*5]; hd[i].dwBufferLength=BS; if(wo) waveOutPrepareHeader(wo,&hd[i],sizeof(WAVEHDR)); }
                long long ts0=-1; DWORD t0=0;
                while(!g_liveStop){
                    PlayFrame f; int kind=0; bool end=false;
                    { std::lock_guard<std::mutex> lk(mx);
                      if(ts0<0 && !vq.empty() && (netDone || vq.back().ts-vq.front().ts>=1000)){
                          ts0=vq.front().ts; t0=GetTickCount();
                          if(wo){ hd[NB].dwBufferLength=LEAD*32; memset(hd[NB].lpData,0,LEAD*32); waveOutWrite(wo,&hd[NB],sizeof(WAVEHDR)); }
                      }
                      if(ts0>=0){
                          long long now=ts0+(long long)(GetTickCount()-t0);
                          if(!vq.empty() && vq.front().ts<=now){ f=std::move(vq.front()); vq.pop_front(); kind=1; }
                          else if(!aq.empty() && aq.front().ts-LEAD<=now){ f=std::move(aq.front()); aq.pop_front(); kind=4; }
                      }
                      end=netDone && vq.empty() && aq.empty(); }
                    if(!kind){ if(end) break; Sleep(5); continue; }
                    if(kind==1){ DWORD wr=0; if(!WriteFile(in,f.data.data(),(DWORD)f.data.size(),&wr,nullptr)) break; }
                    else if(wo && !g_mute) for(int i=0;i<NB;i++) if(!(hd[i].dwFlags&WHDR_INQUEUE)){
                        size_t n=f.data.size()<(size_t)BS*5/2?f.data.size():(size_t)BS*5/2; short*o=(short*)hd[i].lpData;
                        for(size_t k=0;k<n;k++) o[k]=alaw2pcm(f.data[k]);
                        hd[i].dwBufferLength=(DWORD)n*2; waveOutWrite(wo,&hd[i],sizeof(WAVEHDR)); break;
                    }
                }
                CloseHandle(in);
                if(wo){
                    for(bool busy=true;busy && !g_liveStop;){ busy=false; for(int i=0;i<=NB;i++) busy|=(hd[i].dwFlags&WHDR_INQUEUE)!=0; if(busy) Sleep(20); }
                    waveOutReset(wo); for(int i=0;i<=NB;i++) waveOutUnprepareHeader(wo,&hd[i],sizeof(WAVEHDR)); waveOutClose(wo);
                }
            });
            AesEcb ecb; ecb.init(ss.key);
            auto req=[&](const std::string&p){Bytes pk=buildPacket(M_REPLAY,p,ss.key,(u8)ss.sid,0);sendAll(ss.s,pk.data(),pk.size());};
            char p0[256]; sprintf(p0,"{\"pts\":%lld,\"sts\":%lld,\"rtype\":%d,\"time_id\":1,\"vsspec\":0,\"frames\":1000,\"video\":1,\"audio\":1}",seg.startMs,seg.startMs,seg.type);
            req(p0);
            Bytes video,audio; int nv=0; bool done=false; DWORD t0=GetTickCount();
            while(!done && !g_liveStop && (GetTickCount()-t0)/1000.0<seg.durS+30){
                Pkt rp; if(!readPacket(ss.s,ss.key,rp))break;
                if(rp.cmd==CMD_MEDIA){ Bytes pl; long long ts=0; int ft=frameDecrypt(rp.body.data(),rp.body.size(),ecb,ss.key+16,pl,&ts);
                    if(ft==1||ft==2){ video.insert(video.end(),pl.begin(),pl.end()); nv++; std::lock_guard<std::mutex> lk(mx); vq.push_back({ts,std::move(pl)}); }
                    else if(ft==4){ audio.insert(audio.end(),pl.begin(),pl.end()); std::lock_guard<std::mutex> lk(mx); aq.push_back({ts,std::move(pl)}); }
                } else if(rp.cmd==CMD_NOTIFY && !rp.json.empty()){
                    const char*jp=rp.json.c_str();JVal j=jparse(jp);const JVal*par=j.get("params");int iid=par&&par->get("info_id")?(int)par->get("info_id")->n():0;
                    if(iid==4)req("{\"time_id\":1,\"frames\":1000}"); else if(iid==3)done=true;
                }
            }
            { std::lock_guard<std::mutex> lk(mx); netDone=true; }
            feed.join(); show.join();
            endFfmpeg(rd,&g_liveProc,proc);
            if(nv==0) err=T(S_ERR_NOREC);
            else if(done && !g_liveStop) saveMp4(video,audio,nv,seg.durS,outMp4);
        }
    }
    EnterCriticalSection(&g_liveCs); g_playSock=INVALID_SOCKET; LeaveCriticalSection(&g_liveCs);
    if(ss.s!=INVALID_SOCKET) closesocket(ss.s);
    WSACleanup();
    if(!g_liveStop) PostMessageW(hw,WM_LIVEMSG,err?0:2,(LPARAM)err);
    return 0;
}

static void stopLive(){
    g_liveStop=true;
    EnterCriticalSection(&g_liveCs);
    if(g_liveProc) TerminateProcess(g_liveProc,0);
    if(g_audioProc) TerminateProcess(g_audioProc,0);
    if(g_playSock!=INVALID_SOCKET) shutdown(g_playSock,SD_BOTH);
    LeaveCriticalSection(&g_liveCs);
}

// seg < 0 — живое видео, иначе просмотр записи g_segs[seg] (файл для кэша — g_playOut).
static void openLive(int seg){
    if(g_live && seg<0 && g_playSeg<0){ ShowWindow(g_live,SW_RESTORE); SetForegroundWindow(g_live); return; }
    if(g_live) SendMessageW(g_live,WM_CLOSE,0,0);
    if(g_liveThr){ WaitForSingleObject(g_liveThr,20000); CloseHandle(g_liveThr); g_liveThr=nullptr; }
    g_playSeg=seg; g_liveStop=false; g_liveFrame.clear(); g_liveText=seg<0?T(S_CONNECTING):T(S_LOADING_REC);
    if(seg<0) swprintf(g_liveTitle,128,T(S_LIVE_TITLE),g_ipbuf);
    else{ time_t t=(time_t)(g_segs[seg].startMs/1000); struct tm tmv; localtime_s(&tmv,&t); wcsftime(g_liveTitle,128,T(S_REC_TITLE),&tmv); }
    RECT r={0,0,960,540}; AdjustWindowRect(&r,WS_OVERLAPPEDWINDOW,TRUE);
    HMENU mb=CreateMenu(); AppendMenuW(mb,MF_STRING,IDM_MUTE,T(g_mute?S_UNMUTE:S_MUTE));
    g_live=CreateWindowW(L"V380LIVE",seg<0?T(S_LIVE_CONNECTING):g_liveTitle,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,
        r.right-r.left,r.bottom-r.top,nullptr,mb,GetModuleHandleW(nullptr),nullptr);
    ShowWindow(g_live,SW_SHOW);
    g_liveThr=(HANDLE)_beginthreadex(nullptr,0,seg<0?liveThread:playThread,g_live,0,nullptr);
}

static LRESULT CALLBACK LiveProc(HWND h,UINT m,WPARAM wp,LPARAM lp){
    switch(m){
    case WM_ERASEBKGND: return 1;
    case WM_PAINT:{
        PAINTSTRUCT ps; HDC dc=BeginPaint(h,&ps);
        RECT r; GetClientRect(h,&r);
        int cw=r.right,ch=r.bottom,vw=cw,vh=cw*LIVE_H/LIVE_W;
        if(vh>ch){ vh=ch; vw=ch*LIVE_W/LIVE_H; }
        int x=(cw-vw)/2,y=(ch-vh)/2;
        HBRUSH bk=(HBRUSH)GetStockObject(BLACK_BRUSH);
        RECT top={0,0,cw,y},bot={0,y+vh,cw,ch},lft={0,y,x,y+vh},rgt={x+vw,y,cw,y+vh};
        FillRect(dc,&top,bk); FillRect(dc,&bot,bk); FillRect(dc,&lft,bk); FillRect(dc,&rgt,bk);
        EnterCriticalSection(&g_liveCs);
        if(!g_liveFrame.empty()){
            BITMAPINFO bi{}; bi.bmiHeader.biSize=sizeof(bi.bmiHeader); bi.bmiHeader.biWidth=LIVE_W; bi.bmiHeader.biHeight=-LIVE_H;
            bi.bmiHeader.biPlanes=1; bi.bmiHeader.biBitCount=24; bi.bmiHeader.biCompression=BI_RGB;
            SetStretchBltMode(dc,HALFTONE); SetBrushOrgEx(dc,0,0,nullptr);
            StretchDIBits(dc,x,y,vw,vh,0,0,LIVE_W,LIVE_H,g_liveFrame.data(),&bi,DIB_RGB_COLORS,SRCCOPY);
        } else {
            RECT v={x,y,x+vw,y+vh}; FillRect(dc,&v,bk);
            SetBkMode(dc,TRANSPARENT); SetTextColor(dc,RGB(220,220,220)); SelectObject(dc,g_font);
            DrawTextW(dc,g_liveText,-1,&v,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        LeaveCriticalSection(&g_liveCs);
        EndPaint(h,&ps); return 0;}
    case WM_SIZE: InvalidateRect(h,nullptr,FALSE); return 0;
    case WM_LIVEMSG:
        if(wp==1) SetWindowTextW(h,g_liveTitle);
        else if(wp==2){ wchar_t t[160]; swprintf(t,160,T(S_END_OF_REC),g_liveTitle); SetWindowTextW(h,t); }
        else{
            EnterCriticalSection(&g_liveCs); g_liveFrame.clear(); g_liveText=(const wchar_t*)lp; LeaveCriticalSection(&g_liveCs);
            SetWindowTextW(h,T(g_playSeg<0?S_LIVE_NOCONN:S_REC_ERROR)); InvalidateRect(h,nullptr,FALSE);
        }
        return 0;
    case WM_KEYDOWN: if(wp=='M') SendMessageW(h,WM_COMMAND,IDM_MUTE,0); return 0;
    case WM_COMMAND:
        if(LOWORD(wp)==IDM_MUTE){
            g_mute=!g_mute;
            ModifyMenuW(GetMenu(h),IDM_MUTE,MF_BYCOMMAND|MF_STRING,IDM_MUTE,T(g_mute?S_UNMUTE:S_MUTE));
            DrawMenuBar(h);
        }
        return 0;
    case WM_CLOSE: stopLive(); DestroyWindow(h); return 0;
    case WM_DESTROY: g_live=nullptr; return 0;
    }
    return DefWindowProcW(h,m,wp,lp);
}

static void fillList(){
    SendMessageW(g_list,LVM_DELETEALLITEMS,0,0);
    for(size_t i=0;i<g_segs.size();i++){
        wchar_t buf[64];
        LVITEMW it{}; it.mask=LVIF_TEXT; it.iItem=(int)i; it.iSubItem=0;
        swprintf(buf,64,L"%zu",i); it.pszText=buf; SendMessageW(g_list,LVM_INSERTITEMW,0,(LPARAM)&it);
        time_t t=(time_t)(g_segs[i].startMs/1000); struct tm tmv; localtime_s(&tmv,&t);
        wchar_t d[32]; wcsftime(d,32,L"%Y-%m-%d %H:%M:%S",&tmv);
        ListView_SetItemText(g_list,(int)i,1,d);
        swprintf(buf,64,T(S_DUR_SEC),g_segs[i].durS); ListView_SetItemText(g_list,(int)i,2,buf);
        const wchar_t* tn=T(g_segs[i].type==2?S_TYPE_MOTION:(g_segs[i].type==1?S_TYPE_SCHED:S_TYPE_REC));
        ListView_SetItemText(g_list,(int)i,3,(LPWSTR)tn);
    }
    if(g_recmode>=1 && g_combo) SendMessageW(g_combo,CB_SETCURSEL,modeToCombo(g_recmode),0);
    if(g_lightmode>=0) SendMessageW(g_light,CB_SETCURSEL,lightToCombo(g_lightmode),0);
    wchar_t st[256];
    swprintf(st,256,T(S_LIST_STATUS),g_segs.size(),recModeName(),netName().c_str()); setStatus(st);
    updateInfo();
}

static void doDownload(){
    int sel=(int)SendMessageW(g_list,LVM_GETNEXTITEM,(WPARAM)-1,LVNI_SELECTED);
    if(sel<0){ MessageBoxW(g_main,T(S_SELECT_REC),APPTITLE,MB_OK|MB_ICONINFORMATION); return; }
    DlArg* arg=new DlArg(); arg->seg=sel;
    wchar_t def[MAX_PATH]; swprintf(def,MAX_PATH,L"C:\\v380\\rec_%d.mp4",sel);
    wcscpy_s(arg->out,def);
    OPENFILENAMEW ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=g_main;
    ofn.lpstrFilter=T(S_FILTER_MP4); ofn.lpstrFile=arg->out; ofn.nMaxFile=MAX_PATH;
    ofn.lpstrDefExt=L"mp4"; ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
    if(!GetSaveFileNameW(&ofn)){ delete arg; return; }
    EnableWindow(g_btnDl,FALSE); EnableWindow(g_btnPlay,FALSE); EnableWindow(g_btnRef,FALSE);
    setStatus(T(S_DL_CONNECTING));
    _beginthreadex(nullptr,0,downloadThread,arg,0,nullptr);
}

// Просмотр: первый раз запись играет в окне по мере загрузки и сохраняется в %TEMP%380, дальше открывается из файла в плеере Windows.
static void doPlay(){
    int sel=(int)SendMessageW(g_list,LVM_GETNEXTITEM,(WPARAM)-1,LVNI_SELECTED);
    if(sel<0||sel>=(int)g_segs.size()){ MessageBoxW(g_main,T(S_SELECT_REC),APPTITLE,MB_OK|MB_ICONINFORMATION); return; }
    wchar_t dir[MAX_PATH]; GetTempPathW(MAX_PATH,dir); wcscat_s(dir,L"v380"); CreateDirectoryW(dir,nullptr);
    swprintf(g_playOut,MAX_PATH,L"%s\\rec_%lld.mp4",dir,g_segs[sel].startMs);
    if(GetFileAttributesW(g_playOut)!=INVALID_FILE_ATTRIBUTES) ShellExecuteW(g_main,L"open",g_playOut,nullptr,nullptr,SW_SHOWNORMAL);
    else openLive(sel);
}

// --- язык интерфейса: подписи всех элементов; вызывается при создании окна и при смене языка ---
static void comboFill(HWND cb,std::initializer_list<Str> items){
    int sel=(int)SendMessageW(cb,CB_GETCURSEL,0,0); SendMessageW(cb,CB_RESETCONTENT,0,0);
    for(Str s:items) SendMessageW(cb,CB_ADDSTRING,0,(LPARAM)T(s));
    SendMessageW(cb,CB_SETCURSEL,(WPARAM)sel,0);
}
static void applyTexts(){
    SetWindowTextW(g_main,APPTITLE);
    struct{HWND w;Str s;} lbl[]={{g_lblIp,S_LBL_IP},{g_lblPort,S_LBL_PORT},{g_lblPw,S_LBL_PW},{g_btnRef,S_BTN_REFRESH},{g_btnPlay,S_BTN_PLAY},{g_btnDl,S_BTN_DL},
        {g_lblRec,S_LBL_RECMODE},{g_btnApply,S_BTN_APPLY},{g_lblLight,S_LBL_LIGHT},{g_btnLive,S_BTN_LIVE},{g_lblWifi,S_LBL_WIFI},
        {g_lblWpw,S_LBL_PW},{g_btnWifi,S_BTN_WIFI},{g_btnFind,S_BTN_FIND},{g_lblConn,S_LBL_CONN},{g_rbCable,S_RB_CABLE}};
    for(auto&x:lbl) SetWindowTextW(x.w,T(x.s));
    comboFill(g_combo,{S_REC_CONT,S_REC_MOTION});
    comboFill(g_light,{S_LIGHT_OFF,S_LIGHT_ON,S_LIGHT_AUTO});
    Str cols[]={S_COL_NUM,S_COL_DATE,S_COL_DUR,S_COL_TYPE};
    LVCOLUMNW c{}; c.mask=LVCF_TEXT;
    for(int i=0;i<4;i++){ c.pszText=(LPWSTR)T(cols[i]); SendMessageW(g_list,LVM_SETCOLUMNW,i,(LPARAM)&c); }
    syncRadios();
    if(g_segs.empty()){ setStatus(T(S_HINT)); updateInfo(); }
    else{
        int sel=(int)SendMessageW(g_list,LVM_GETNEXTITEM,(WPARAM)-1,LVNI_SELECTED);
        fillList();
        if(sel>=0) ListView_SetItemState(g_list,sel,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
    }
    HMENU mb=GetMenu(g_main);
    if(mb && g_menuLang){
        ModifyMenuW(mb,0,MF_BYPOSITION|MF_POPUP|MF_STRING,(UINT_PTR)g_menuLang,T(S_MENU_LANG));
        CheckMenuRadioItem(g_menuLang,IDM_LANG_EN,IDM_LANG_RU,g_lang?IDM_LANG_RU:IDM_LANG_EN,MF_BYCOMMAND);
        DrawMenuBar(g_main);
    }
    if(g_live){ ModifyMenuW(GetMenu(g_live),IDM_MUTE,MF_BYCOMMAND|MF_STRING,IDM_MUTE,T(g_mute?S_UNMUTE:S_MUTE)); DrawMenuBar(g_live); }
}
static void setLang(int lang){
    g_lang=lang; WritePrivateProfileStringW(L"ui",L"lang",lang?L"ru":L"en",iniPath().c_str());
    applyTexts();
}

static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM wp,LPARAM lp){
    switch(m){
    case WM_CREATE:{
        g_main=h;
        g_font=(HFONT)GetStockObject(DEFAULT_GUI_FONT);
        GetPrivateProfileStringW(L"camera",L"ip",L"",g_ipbuf,64,iniPath().c_str());
        GetPrivateProfileStringW(L"camera",L"password",L"",g_pwbuf,64,iniPath().c_str());
        g_lblIp=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,10,14,70,20,h,0,0,0);
        g_ip=CreateWindowW(L"EDIT",g_ipbuf,WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,85,12,92,22,h,(HMENU)IDC_IP,0,0);
        g_lblPort=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,183,14,27,20,h,0,0,0);
        { wchar_t pb[16]; swprintf(pb,16,L"%d",(int)GetPrivateProfileIntW(L"camera",L"port",8089,iniPath().c_str()));
          g_port=CreateWindowW(L"EDIT",pb,WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER,211,12,42,22,h,(HMENU)IDC_PORT,0,0);
          SendMessageW(g_port,EM_LIMITTEXT,5,0); }
        g_lblPw=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,259,14,50,20,h,0,0,0);
        g_pw=CreateWindowW(L"EDIT",g_pwbuf,WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,310,12,92,22,h,(HMENU)IDC_PW,0,0);
        g_btnRef=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,410,11,150,24,h,(HMENU)IDC_REFRESH,0,0);
        g_btnPlay=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,570,11,75,24,h,(HMENU)IDC_PLAY,0,0);
        g_btnDl=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,655,11,75,24,h,(HMENU)IDC_DOWNLOAD,0,0);
        // Строка 2: режим записи и подсветка
        g_lblRec=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,10,44,95,20,h,0,0,0);
        g_combo=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,110,41,120,200,h,(HMENU)IDC_RECMODE,0,0);
        g_btnApply=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,240,40,130,24,h,(HMENU)IDC_APPLYREC,0,0);
        g_lblLight=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,385,44,35,20,h,0,0,0);
        g_light=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,420,41,140,200,h,(HMENU)IDC_LIGHT,0,0);
        g_btnLive=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,570,40,160,24,h,(HMENU)IDC_LIVE,0,0);
        // Строка 3: Wi-Fi
        g_lblWifi=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,10,74,95,20,h,0,0,0);
        g_wssid=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,110,71,120,22,h,(HMENU)IDC_WSSID,0,0);
        g_lblWpw=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,240,74,55,20,h,0,0,0);
        g_wpw=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,295,71,110,22,h,(HMENU)IDC_WPW,0,0);
        g_btnWifi=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,410,70,150,24,h,(HMENU)IDC_WIFI,0,0);
        g_btnFind=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,570,70,160,24,h,(HMENU)IDC_FIND,0,0);
        // Строка 4: выбор подключения (провод / Wi-Fi) и в какой сети камера сейчас
        g_lblConn=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,10,104,85,20,h,0,0,0);
        g_rbCable=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|WS_GROUP|BS_RADIOBUTTON,100,101,105,22,h,(HMENU)IDC_RBCABLE,0,0);
        g_rbWifi=CreateWindowW(L"BUTTON",L"",WS_CHILD|WS_VISIBLE|BS_RADIOBUTTON,210,101,190,22,h,(HMENU)IDC_RBWIFI,0,0);
        g_netlbl=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_RIGHT,400,104,330,18,h,0,0,0);
        // Строка 5: часовой пояс камеры
        g_tzlbl=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP,10,128,720,18,h,0,0,0);
        g_list=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,
            10,150,720,296,h,(HMENU)IDC_LIST,0,0);
        ListView_SetExtendedListViewStyle(g_list,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM; c.pszText=(LPWSTR)L"";
        int W[]={50,180,110,220};
        for(int i=0;i<4;i++){c.iSubItem=i;c.cx=W[i];SendMessageW(g_list,LVM_INSERTCOLUMNW,i,(LPARAM)&c);}
        g_status=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP,10,452,720,20,h,0,0,0);
        EnumChildWindows(h,[](HWND c2,LPARAM)->BOOL{ SendMessageW(c2,WM_SETFONT,(WPARAM)g_font,TRUE); return TRUE; },0);
        { LOGFONTW lf; GetObjectW(g_font,sizeof(lf),&lf); lf.lfWeight=FW_BOLD; g_fontBold=CreateFontIndirectW(&lf); }
        SendMessageW(g_netlbl,WM_SETFONT,(WPARAM)g_fontBold,TRUE); SendMessageW(g_tzlbl,WM_SETFONT,(WPARAM)g_fontBold,TRUE);
        // Выбранное подключение и сеть камеры с прошлого раза: без кабеля «По проводу» сразу недоступен.
        g_sel=GetPrivateProfileIntW(L"camera",L"conn",8,iniPath().c_str())==2?2:8;
        g_lastLink=(int)GetPrivateProfileIntW(L"camera",L"link",0,iniPath().c_str()); if(g_lastLink!=2&&g_lastLink!=8) g_lastLink=-1;
        { wchar_t s[64]; GetPrivateProfileStringW(L"camera",L"wifi_ssid",L"",s,64,iniPath().c_str()); g_netssid=wtoutf8(s); }
        if(g_lastLink==2) g_sel=2;
        loadProfileIp(g_sel); applyTexts();
        SendMessageW(g_combo,CB_SETCURSEL,0,0);
        return 0;}
    case WM_CTLCOLORSTATIC:{
        // Цвет строки подключения: зелёный — провод, синий — Wi-Fi, серый — неизвестно; пояс камеры красным, если не совпадает с ПК.
        HDC dc=(HDC)wp; HWND c=(HWND)lp;
        if(c!=g_netlbl && c!=g_tzlbl) break;
        COLORREF col=c==g_netlbl?(g_netmode==8?RGB(0,128,0):(g_netmode>0?RGB(0,90,200):RGB(110,110,110)))
                                :(g_camtz!=-1 && tzMinutes(g_camtz)!=tzMinutes(tzVal())?RGB(200,0,0):RGB(0,128,0));
        SetTextColor(dc,col); SetBkColor(dc,GetSysColor(COLOR_BTNFACE));
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);}
    case WM_SIZE:{
        RECT r; GetClientRect(h,&r);
        MoveWindow(g_netlbl,r.right-340,104,330,18,TRUE);
        MoveWindow(g_tzlbl,10,128,r.right-20,18,TRUE);
        MoveWindow(g_list,10,150,r.right-20,r.bottom-150-26,TRUE);
        MoveWindow(g_status,10,r.bottom-22,r.right-20,20,TRUE);
        return 0;}
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if(id==IDM_LANG_EN || id==IDM_LANG_RU) setLang(id==IDM_LANG_RU?1:0);
        else if((id==IDC_RBCABLE || id==IDC_RBWIFI) && HIWORD(wp)==BN_CLICKED){
            if(g_busy) syncRadios(); else selectConn(id==IDC_RBWIFI?2:8);
        } else if(id==IDC_REFRESH && !g_busy){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            EnableWindow(g_btnRef,FALSE); EnableWindow(g_btnDl,FALSE);
            _beginthreadex(nullptr,0,refreshThread,nullptr,0,nullptr);
        } else if(id==IDC_DOWNLOAD && !g_busy){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            doDownload();
        } else if(id==IDC_PLAY && !g_busy){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            doPlay();
        } else if(id==IDC_LIGHT && HIWORD(wp)==CBN_SELCHANGE){
            int idx=(int)SendMessageW(g_light,CB_GETCURSEL,0,0);
            if(g_busy){ SendMessageW(g_light,CB_SETCURSEL,g_lightmode>=0?lightToCombo(g_lightmode):-1,0); return 0; }
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            EnableWindow(g_light,FALSE); setStatus(T(S_LIGHT_SENDING));
            _beginthreadex(nullptr,0,lightThread,(void*)(INT_PTR)comboToLight(idx),0,nullptr);
        } else if(id==IDC_APPLYREC && !g_busy){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            int idx=(int)SendMessageW(g_combo,CB_GETCURSEL,0,0); if(idx<0)idx=0;
            g_applyMode=comboToMode(idx);
            EnableWindow(g_btnApply,FALSE); EnableWindow(g_btnRef,FALSE); EnableWindow(g_btnDl,FALSE);
            setStatus(T(S_REC_SENDING));
            _beginthreadex(nullptr,0,applyRecThread,nullptr,0,nullptr);
        } else if(id==IDC_LIVE){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            openLive(-1);
        } else if(id==IDC_WIFI && !g_busy){
            GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            GetWindowTextW(g_wssid,g_ssidbuf,64); GetWindowTextW(g_wpw,g_wpwbuf,64);
            if(!g_ssidbuf[0]){ MessageBoxW(h,T(S_ENTER_SSID),APPTITLE,MB_OK|MB_ICONINFORMATION); return 0; }
            if((wcsstr(g_ssidbuf,L"5G")||wcsstr(g_ssidbuf,L"5g")) &&
               MessageBoxW(h,T(S_5G_WARN),APPTITLE,MB_YESNO|MB_ICONWARNING)!=IDYES) return 0;
            EnableWindow(g_btnWifi,FALSE); EnableWindow(g_btnFind,FALSE); EnableWindow(g_btnRef,FALSE);
            setStatus(T(S_WIFI_SENDING));
            _beginthreadex(nullptr,0,wifiThread,nullptr,0,nullptr);
        } else if(id==IDC_FIND && !g_busy){
            GetWindowTextW(g_pw,g_pwbuf,64); readPort();
            EnableWindow(g_btnWifi,FALSE); EnableWindow(g_btnFind,FALSE); EnableWindow(g_btnRef,FALSE);
            _beginthreadex(nullptr,0,findThread,nullptr,0,nullptr);
        }
        return 0;}
    case WM_NOTIFY:{
        LPNMHDR nh=(LPNMHDR)lp;
        if(nh->idFrom==IDC_LIST && nh->code==NM_DBLCLK){ if(!g_busy){ GetWindowTextW(g_ip,g_ipbuf,64); GetWindowTextW(g_pw,g_pwbuf,64); readPort(); doPlay(); } }
        return 0;}
    case WM_LISTREADY:
        SetWindowTextW(g_ip,g_ipbuf);   // адрес мог смениться: камера найдена поиском по сети
        WritePrivateProfileStringW(L"camera",L"ip",g_ipbuf,iniPath().c_str());
        WritePrivateProfileStringW(L"camera",L"password",g_pwbuf,iniPath().c_str());
        { wchar_t pb[16]; swprintf(pb,16,L"%d",PORT); WritePrivateProfileStringW(L"camera",L"port",pb,iniPath().c_str()); }
        // Камера ответила по этому адресу — значит, он относится к сети, в которой она сейчас; запоминаем как адрес этого варианта.
        if(g_netmode==8 || g_netmode==2){
            g_lastLink=g_sel=g_netmode; saveProfileIp(g_netmode,g_ipbuf);
            WritePrivateProfileStringW(L"camera",L"link",g_netmode==2?L"2":L"8",iniPath().c_str());
            WritePrivateProfileStringW(L"camera",L"conn",g_netmode==2?L"2":L"8",iniPath().c_str());
            WritePrivateProfileStringW(L"camera",L"wifi_ssid",ssidW().c_str(),iniPath().c_str());
        }
        syncRadios();
        fillList(); EnableWindow(g_btnRef,TRUE); EnableWindow(g_btnDl,TRUE); EnableWindow(g_btnApply,TRUE); return 0;
    case WM_OPFAIL: setStatus(T(S_OPFAIL)); updateInfo(); EnableWindow(g_btnRef,TRUE); EnableWindow(g_btnDl,TRUE); EnableWindow(g_btnApply,TRUE); return 0;
    case WM_RECDONE:{
        EnableWindow(g_btnRef,TRUE); EnableWindow(g_btnDl,TRUE); EnableWindow(g_btnApply,TRUE);
        if(wp){ if(g_combo)SendMessageW(g_combo,CB_SETCURSEL,modeToCombo(g_recmode),0);
            wchar_t s[160]; swprintf(s,160,T(S_REC_DONE),recModeName()); setStatus(s);
            MessageBoxW(g_main,T(S_REC_APPLIED),APPTITLE,MB_OK|MB_ICONINFORMATION);
        } else setStatus(T(S_REC_FAIL));
        return 0;}
    case WM_WIFIDONE:{
        EnableWindow(g_btnWifi,TRUE); EnableWindow(g_btnFind,TRUE); EnableWindow(g_btnRef,TRUE);
        if(wp==1){ wchar_t s[256]; swprintf(s,256,T(S_WIFI_ACCEPTED),g_ssidbuf); setStatus(s);
            g_netmode=-1; updateInfo();
            wchar_t msg[512]; swprintf(msg,512,T(S_WIFI_ACCEPTED_MSG),g_ssidbuf);
            MessageBoxW(g_main,msg,APPTITLE,MB_OK|MB_ICONINFORMATION);
        } else setStatus(wp==2?T(S_WIFI_REJECTED):T(S_ERR_CONNECT));
        return 0;}
    case WM_FOUND:{
        EnableWindow(g_btnWifi,TRUE); EnableWindow(g_btnFind,TRUE); EnableWindow(g_btnRef,TRUE);
        if(g_foundIp[0]){ SetWindowTextW(g_ip,g_foundIp); wchar_t s[128]; swprintf(s,128,T(S_FOUND),g_foundIp); setStatus(s); }
        else setStatus(T(S_NOT_FOUND));
        return 0;}
    case WM_DLPROGRESS:{ wchar_t s[128]; swprintf(s,128,T(S_DL_PROGRESS),(int)wp,(int)lp); setStatus(s); return 0; }
    case WM_DLDONE:{
        EnableWindow(g_btnRef,TRUE); EnableWindow(g_btnDl,TRUE); EnableWindow(g_btnPlay,TRUE);
        int nv=((int)lp>>16)&0xffff, na=(int)lp&0xffff;
        bool mp4=GetFileAttributesW(g_lastOut)!=INVALID_FILE_ATTRIBUTES;
        if(wp && mp4){
            wchar_t s[160]; swprintf(s,160,T(S_DL_DONE),nv,na); setStatus(s);
            if(MessageBoxW(g_main,T(S_DL_OPEN),APPTITLE,MB_YESNO|MB_ICONINFORMATION)==IDYES)
                ShellExecuteW(g_main,L"open",g_lastOut,nullptr,nullptr,SW_SHOWNORMAL);
        } else if(wp) setStatus(T(S_DL_NOMP4));
        else setStatus(T(S_DL_FAIL));
        return 0;}
    case WM_LIGHTDONE:{
        EnableWindow(g_light,TRUE);
        SendMessageW(g_light,CB_SETCURSEL,g_lightmode>=0?lightToCombo(g_lightmode):-1,0);
        setStatus(wp?T(g_lightmode==1?S_LIGHT_ON_ST:(g_lightmode==2?S_LIGHT_OFF_ST:S_LIGHT_AUTO_ST)):T(S_LIGHT_FAIL));
        return 0;}
    case WM_DESTROY: stopLive(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h,m,wp,lp);
}

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE,LPWSTR,int nShow){
    INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&ic);
    WNDCLASSW wc{}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.lpszClassName=L"V380GUI";
    wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    wc.hIcon=LoadIcon(nullptr,IDI_APPLICATION);
    RegisterClassW(&wc);
    WNDCLASSW lc=wc; lc.lpfnWndProc=LiveProc; lc.lpszClassName=L"V380LIVE"; lc.hbrBackground=nullptr;
    RegisterClassW(&lc);
    InitializeCriticalSection(&g_liveCs);
    // Язык интерфейса с прошлого раза; по умолчанию английский. Меню Language переключает его на лету.
    wchar_t lg[8]; GetPrivateProfileStringW(L"ui",L"lang",L"en",lg,8,iniPath().c_str()); g_lang=wcscmp(lg,L"ru")==0?1:0;
    HMENU mb=CreateMenu(); g_menuLang=CreatePopupMenu();
    AppendMenuW(g_menuLang,MF_STRING,IDM_LANG_EN,L"English");
    AppendMenuW(g_menuLang,MF_STRING,IDM_LANG_RU,L"Русский");
    AppendMenuW(mb,MF_POPUP,(UINT_PTR)g_menuLang,T(S_MENU_LANG));
    g_main=CreateWindowW(L"V380GUI",APPTITLE,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,760,595,nullptr,mb,hInst,nullptr);
    ShowWindow(g_main,nShow); UpdateWindow(g_main);
    MSG msg; while(GetMessageW(&msg,nullptr,0,0)){ TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
