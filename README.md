# PortPainter

PortPainter is a network and serial port monitoring tool built with PyQt6. It provides real-time visualization, analytics, and logging of network traffic, with support for multiple themes, languages, and customizable settings. The application includes features like threat intelligence integration, data export, and system tray notifications.

## Features
- **Real-time Monitoring**: Tracks network and serial port activity with detailed metrics.
- **Visualization**: Displays port activity using 2D/3D scatter plots with zoom and pause controls.
- **Analytics**: Provides graphical insights into network traffic patterns.
- **Multi-language Support**: Available in English, Persian, and Chinese.
- **Theming**: Supports Windows 11, dark, red-blue, and default themes.
- **Filtering**: Allows filtering by port range, protocol, IP, and process.
- **Export Options**: Export data to CSV, images, or configuration files.
- **Alerts**: Notifies users of new or closed ports via system tray.
- **Database Integration**: Stores port activity and settings in SQLite.
- **Traffic Simulation**: Simulates network traffic for testing purposes.

## Installation

1. **Install Python**: Ensure Python 3.8+ is installed.
2. **Install Dependencies**: Run the following command to install required packages:
   ```bash
   pip install PyQt6 psutil pyqtgraph numpy matplotlib scapy requests qdarkstyle
   ```
3. **Download the Code**: Obtain the source code from the GitHub repository.
4. **Run the Application**: Execute the main script:
   ```bash
   python portpainter.py
   ```

## Usage
- **Start Monitoring**: Click "Start Monitoring" to begin tracking network and serial ports.
- **Visualize Data**: Switch to the "Visualization" tab to view real-time port activity.
- **Analyze Traffic**: Use the "Analytics" tab for traffic insights.
- **Apply Filters**: Configure filters in the dock widget to focus on specific ports or protocols.
- **Export Data**: Save data as CSV or images via the "File > Export" menu.
- **Customize Settings**: Adjust themes, languages, and refresh rates in the "Settings" dialog.
- **Simulate Traffic**: Use the "Simulate Traffic" button for testing.

## System Requirements
- **Operating System**: Windows, Linux, or macOS
- **Python**: Version 3.8 or higher
- **RAM**: 4GB minimum
- **Dependencies**: PyQt6, psutil, pyqtgraph, numpy, matplotlib, scapy, requests, qdarkstyle

## Contributing
Contributions are welcome! Please submit pull requests or open issues for bugs, feature requests, or improvements.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

# نقاش پورت

نقاش پورت یک ابزار نظارت بر پورت‌های شبکه و سریال است که با PyQt6 ساخته شده است. این ابزار امکان تجسم بلادرنگ، تحلیل و ثبت فعالیت‌های شبکه را فراهم می‌کند و از چندین تم، زبان و تنظیمات قابل سفارشی‌سازی پشتیبانی می‌کند. ویژگی‌هایی مانند ادغام هوش تهدید، صادرات داده و اعلان‌های سینی سیستم نیز در این برنامه گنجانده شده‌اند.

## ویژگی‌ها
- **نظارت بلادرنگ**: ردیابی فعالیت پورت‌های شبکه و سریال با معیارهای دقیق.
- **تجسم**: نمایش فعالیت پورت‌ها با استفاده از نمودارهای پراکنده دوبعدی/سه‌بعدی با کنترل‌های زوم و مکث.
- **تحلیل**: ارائه بینش‌های گرافیکی از الگوهای ترافیک شبکه.
- **پشتیبانی از چند زبان**: در دسترس به زبان‌های انگلیسی، فارسی و چینی.
- **تم‌ها**: پشتیبانی از تم‌های ویندوز 11، تاریک، قرمز-آبی و پیش‌فرض.
- **فیلتر کردن**: امکان فیلتر بر اساس محدوده پورت، پروتکل، آی‌پی و فرآیند.
- **گزینه‌های صادرات**: ذخیره داده‌ها به صورت CSV، تصاویر یا فایل‌های پیکربندی.
- **هشدارها**: اطلاع‌رسانی به کاربران درباره پورت‌های جدید یا بسته شده از طریق سینی سیستم.
- **ادغام با پایگاه داده**: ذخیره فعالیت پورت‌ها و تنظیمات در SQLite.
- **شبیه‌سازی ترافیک**: شبیه‌سازی ترافیک شبکه برای اهداف آزمایشی.

## نصب

1. **نصب پایتون**: اطمینان حاصل کنید که پایتون نسخه 3.8 یا بالاتر نصب شده است.
2. **نصب وابستگی‌ها**: دستور زیر را برای نصب بسته‌های مورد نیاز اجرا کنید:
   ```bash
   pip install PyQt6 psutil pyqtgraph numpy matplotlib scapy requests qdarkstyle
   ```
3. **دانلود کد**: کد منبع را از مخزن گیت‌هاب دریافت کنید.
4. **اجرای برنامه**: اسکریپت اصلی را اجرا کنید:
   ```bash
   python portpainter.py
   ```

## استفاده
- **شروع نظارت**: روی «شروع نظارت» کلیک کنید تا ردیابی پورت‌های شبکه و سریال آغاز شود.
- **تجسم داده‌ها**: به تب «تجسم» بروید تا فعالیت پورت‌ها را به‌صورت بلادرنگ مشاهده کنید.
- **تحلیل ترافیک**: از تب «تحلیل» برای بینش‌های ترافیکی استفاده کنید.
- **اعمال فیلترها**: فیلترها را در ویجت داک برای تمرکز بر پورت‌ها یا پروتکل‌های خاص پیکربندی کنید.
- **صادرات داده‌ها**: داده‌ها را به صورت CSV یا تصاویر از طریق منوی «فایل > صادرات» ذخیره کنید.
- **سفارشی‌سازی تنظیمات**: تم‌ها، زبان‌ها و نرخ‌های تازه‌سازی را در گفت‌وگوی «تنظیمات» تنظیم کنید.
- **شبیه‌سازی ترافیک**: از دکمه «شبیه‌سازی ترافیک» برای آزمایش استفاده کنید.

## نیازمندی‌های سیستم
- **سیستم‌عامل**: ویندوز، لینوکس یا مک‌او‌اس
- **پایتون**: نسخه 3.8 یا بالاتر
- **رم**: حداقل 4 گیگابایت
- **وابستگی‌ها**: PyQt6، psutil، pyqtgraph، numpy، matplotlib، scapy، requests، qdarkstyle

## مشارکت
مشارکت‌ها استقبال می‌شوند! لطفاً درخواست‌های کشش را ارسال کنید یا برای گزارش اشکالات، درخواست ویژگی‌ها یا بهبودها، مسائل را باز کنید.

## مجوز
این پروژه تحت مجوز MIT منتشر شده است. برای جزئیات، فایل [LICENSE](LICENSE) را ببینید.

---

# 端口画家

端口画家是一款使用 PyQt6 构建的网络和串口监控工具。它提供实时可视化、分析和网络流量日志记录，支持多种主题、语言和可定制设置。该应用程序包括威胁情报集成、数据导出和系统托盘通知等功能。

## 功能
- **实时监控**：跟踪网络和串口活动，提供详细指标。
- **可视化**：使用二维/三维散点图显示端口活动，支持缩放和暂停控制。
- **分析**：提供网络流量模式的图形化洞察。
- **多语言支持**：支持英语、波斯语和中文。
- **主题**：支持 Windows 11、暗色、红蓝和默认主题。
- **过滤**：支持按端口范围、协议、IP 和进程进行过滤。
- **导出选项**：将数据导出为 CSV、图像或配置文件。
- **警报**：通过系统托盘通知用户新端口或关闭端口。
- **数据库集成**：将端口活动和设置存储在 SQLite 中。
- **流量模拟**：模拟网络流量以进行测试。

## 安装

1. **安装 Python**：确保已安装 Python 3.8 或更高版本。
2. **安装依赖项**：运行以下命令安装所需包：
   ```bash
   pip install PyQt6 psutil pyqtgraph numpy matplotlib scapy requests qdarkstyle
   ```
3. **下载代码**：从 GitHub 仓库获取源代码。
4. **运行应用程序**：执行主脚本：
   ```bash
   python portpainter.py
   ```

## 使用
- **开始监控**：点击“开始监控”以跟踪网络和串口。
- **可视化数据**：切换到“可视化”选项卡以查看实时端口活动。
- **分析流量**：使用“分析”选项卡获取流量洞察。
- **应用过滤器**：在停靠部件中配置过滤器以关注特定端口或协议。
- **导出数据**：通过“文件 > 导出”菜单将数据保存为 CSV 或图像。
- **自定义设置**：在“设置”对话框中调整主题、语言和刷新率。
- **模拟流量**：使用“模拟流量”按钮进行测试。

## 系统要求
- **操作系统**：Windows、Linux 或 macOS
- **Python**：3.8 或更高版本
- **内存**：最低 4GB
- **依赖项**：PyQt6、psutil、pyqtgraph、numpy、matplotlib、scapy、requests、qdarkstyle

## 贡献
欢迎贡献！请提交拉取请求或为错误、功能请求或改进开具问题。

## 许可证
本项目采用 MIT 许可证发布。详情请见 [LICENSE](LICENSE) 文件。