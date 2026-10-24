# LinkBridge — جسر محلي آمن لنقل النصوص والملفات بين Android 9+ وWindows

**عمل محمد البكير**

نظام برمجي متكامل ومفتوح المصدر يتكون من تطبيق **Android أصلي (Kotlin / API 28+)** وتطبيق **Windows مكتبي (Python + PySide6 + SQLite)** لتبادل النصوص ومحتويات الحافظة والملفات والمجلدات بسرعة وخصوصية تامة عبر **الشبكة المحلية Wi-Fi** أو **نقطة اتصال الهاتف (Hotspot)** أو **Bluetooth Classic (RFCOMM)** دون أي اعتماد على الإنترنت أو الخدمات السحابية.

---

## 1. المزايا المعمارية والأمنية

| المجال | التصميم المنفّذ في LinkBridge |
| :--- | :--- |
| **مسارات الاتصال الثلاثة** | 1. **Wi-Fi المحلي (LAN)**: المسار المفضل والأسرع للملفات الكبيرة (كتل 64 KiB + TLS 1.3/1.2).<br>2. **نقطة اتصال الهاتف (Hotspot)**: يعمل مباشرة بين الهاتف واللابتوب دون الحاجة إلى راوتر أو إنترنت.<br>3. **Bluetooth Classic (RFCOMM)**: مسار ثالث للنصوص والملفات الصغيرة والمتوسطة عند غياب الشبكة (كتل 16 KiB + تشفير تطبيقي ECDH P-256 + HKDF-SHA256 + AES-256-GCM). |
| **الأمان والمصادقة** | لا توجد مفاتيح ثابتة مشتركة؛ يولّد كل جهاز شهادة **X.509 ECDSA P-256** خاصة به وبصمة **SHA-256**، ويتم الاقتران عبر رمز **PIN من 6 أرقام** أو مسح **QR Code** قصير العمر (5 دقائق) مع جلسات مصادق عليها قصيرة العمر (`SessionInfo`) وقابلة للإبطال الفوري. |
| **نظام الحافظة الذكي (Clipboard Bridge)** | مزامنة في الاتجاهين (يدوية أو تلقائية لكل اتجاه على حدة)، بصمة محتوى SHA-256 ومعرّف فريد لكل عنصر، منع صارم لحلقات التكرار (Sync Loop Prevention)، منع الإرسال المكرر، استثناء التطبيقات الحساسة على Windows (مثل `KeePass.exe` و`1Password.exe` و`Bitwarden.exe`)، وسجل محلي في SQLite قابل للبحث والنسخ وإعادة الإرسال والحذف. |
| **نقل الملفات المتدفق والقابل للاستئناف** | فصل تام بين رسائل التحكم JSON وتدفق كتل الملفات الثنائية، حفظ مؤقت بامتداد `.lbpart` يدعم **الاستئناف التلقائي (Resume)** من آخر كتلة عند انقطاع الاتصال، التحقق الإلزامي من الحجم والبصمة **SHA-256** بعد الاكتمال، حماية صارمة من اجتياز المسارات (Path Traversal)، ومنع الكتابة فوق الملفات الموجودة بتوليد `اسم (1).امتداد`. |
| **تجربة الاستخدام واللغات** | واجهة عربية **RTL** وإنجليزية **LTR**، وضع داكن وفاتح، أيقونة في منطقة إشعارات النظام (System Tray) على Windows، خيار التشغيل مع بدء Windows بموافقة المستخدم ودون صلاحيات Administrator، وقسم «حول التطبيق» يتضمن عبارة **«عمل محمد البكير»**. |

---

## 2. هيكل المشروع

```text
LinkBridge/
├── android/                  # تطبيق Android الأصلي (Kotlin, minSdk 28 / Android 9+)
│   ├── app/
│   │   ├── build.gradle.kts
│   │   ├── proguard-rules.pro
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/linkbridge/app/
│   │       │   ├── protocol/LinkBridgeProtocol.kt
│   │       │   ├── data/LinkBridgeDatabase.kt
│   │       │   ├── clipboard/AndroidClipboardController.kt
│   │       │   ├── files/SafFileTransferController.kt
│   │       │   ├── service/LinkBridgeForegroundService.kt
│   │       │   └── ui/{MainActivity.kt, ShareReceiverActivity.kt}
│   │       └── res/{values,values-ar}/strings.xml
│   ├── build.gradle.kts
│   └── settings.gradle.kts
├── windows/                  # تطبيق Windows المكتبي (Python 3.11+ / PySide6 / SQLite)
│   ├── app.py                # نقطة التشغيل الرئيسية والواجهة الرسومية + وضع الفحص الذاتي
│   ├── bridge_node.py        # وحدة التحكم الموحدة بالجلسات والمسارات والاقتران
│   ├── clipboard_manager.py  # محرك الحافظة والمزامنة الذكية ومنع التكرار
│   ├── file_manager.py       # محرك نقل الملفات المتدفق والاستئناف والحماية من Path Traversal
│   ├── storage.py            # قاعدة بيانات SQLite المحلية للإعدادات والسجل والأجهزة المقترنة
│   ├── startup_and_tray.py   # إدارة بدء التشغيل مع Windows (HKCU) وأيقونة النظام
│   ├── i18n.py               # القواميس العربية (RTL) والإنجليزية (LTR) والسمات البصرية
│   └── requirements.txt
├── protocol/                 # حزمة البروتوكول والأمان المشتركة (LB01 v1.0)
│   ├── constants.py
│   ├── crypto.py
│   ├── messages.py
│   └── transport.py
├── tests/                    # اختبارات الوحدة والتكامل الشاملة
│   └── test_linkbridge_suite.py
├── docs/                     # التوثيق التقني والأمني وتقرير الاختبارات الفعلي
│   ├── PROTOCOL.md
│   ├── SECURITY_AND_PERMISSIONS.md
│   ├── TROUBLESHOOTING.md
│   ├── TEST_REPORT.md
│   └── test_results.json
├── scripts/                  # سكربتات البناء والتشغيل والاختبار
│   ├── build_windows.ps1
│   ├── build_android.sh
│   └── run_tests.sh
├── README_AR.md
├── README_EN.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

---

## 3. طريقة التشغيل السريع خطوة بخطوة

### أولًا: تشغيل تطبيق Windows
1. تأكد من توفر Python 3.10 أو أحدث على جهاز Windows 10/11، ثم ثبّت المتطلبات:
   ```powershell
   pip install -r windows/requirements.txt
   ```
2. شغّل التطبيق المكتبي:
   ```powershell
   python windows/app.py
   ```
3. للتحقق السريع من البيئة والشهادات عبر سطر الأوامر:
   ```powershell
   python windows/app.py --self-check
   ```
4. لبناء حزمة تنفيذية مستقلة (`LinkBridge.exe`) لا تتطلب تثبيت Python لدى المستخدم النهائي:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/build_windows.ps1
   ```

### ثانيًا: بناء وتثبيت تطبيق Android 9+
1. افتح مجلد `android/` داخل **Android Studio** (أو تأكد من ضبط `ANDROID_HOME` وتوفر JDK 17).
2. نفّذ سكربت البناء:
   ```bash
   bash scripts/build_android.sh
   ```
3. ثبّت ملف الـ APK الناتج (`app/build/outputs/apk/debug/app-debug.apk`) على هاتف Android 9 (API 28) أو أحدث.

### ثالثًا: خطوات الربط والاقتران بين الهاتف واللابتوب
1. **اختيار مسار الاتصال**:
   - **الوضع الأول (Wi-Fi المحلي)**: وصّل الهاتف واللابتوب بنفس شبكة Wi-Fi.
   - **الوضع الثاني (نقطة اتصال الهاتف Hotspot)**: فعّل نقطة الاتصال في الهاتف ووصّل اللابتوب بها (لا يلزم وجود إنترنت).
   - **الوضع الثالث (Bluetooth RFCOMM)**: اققرن الهاتف واللابتوب من إعدادات Bluetooth في النظام أولًا، ثم اختر مسار `Bluetooth Classic (RFCOMM)` داخل التطبيق.
2. في تطبيق Windows، اضغط **«تشغيل الاستماع المحلي»** ثم اضغط **«توليد رمز اقتران جديد (PIN / QR)»**.
3. في تطبيق Android، أدخل عنوان `IP:Port` الظاهر في شاشة Windows (أو اختر الجهاز المقترن عبر Bluetooth) وأدخل رمز الـ **PIN المكون من 6 أرقام**، ثم اضغط **«اتصال ومصادقة»**.
4. بعد نجاح الاقتران الأول، تُحفظ بصمة الشهادة ومفتاح الرابط المشتق في قاعدة بيانات SQLite على الجهازين، وتتم الاتصالات التالية تلقائيًا بجلسات قصيرة العمر دون الحاجة لإعادة إدخال الـ PIN ما لم يتم إبطال الثقة.

---

## 4. قيود Android 9+ على الحافظة وكيفية التعامل معها بصدق

- على **Android 9 (API 28)**: يسمح النظام بمراقبة تغير الحافظة أثناء عمل الخدمة الأمامية (Foreground Service)، لكن بعض واجهات الشركات المصنعة قد تقيّد العمليات الخلفية لتوفير البطارية.
- على **Android 10+ (API 29+)**: يمنع نظام Android قراءة الحافظة في الخلفية إلا للتطبيق الذي يمتلك تركيز النافذة (Window Focus).
- **الحل المعماري في LinkBridge**: لا يستخدم التطبيق إطلاقًا صلاحيات `AccessibilityService` للتجسس أو التحايل على النظام؛ بل يوفّر 3 مسارات رسمية سريعة وموثوقة 100%:
  1. **مشاركة النظام (Share Sheet)**: مشاركة أي نص أو رابط أو كود أو ملفات من أي تطبيق مباشرة إلى **LinkBridge**.
  2. **إشعار الإرسال السريع**: زر إرسال فوري في الإشعار الدائم يفتح نافذة الإرسال ويرسل محتوى الحافظة بضغطة واحدة.
  3. **زر الإرسال اليدوي والمزامنة عند فتح التطبيق**.
