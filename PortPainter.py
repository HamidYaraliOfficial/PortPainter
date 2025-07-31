import sys
import asyncio
import platform
import socket
import psutil
import threading
import queue
import time
import logging
import json
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                            QTabWidget, QPushButton, QTableWidget, QTableWidgetItem, QComboBox,
                            QLabel, QLineEdit, QToolBar, QStatusBar, QMenuBar, QMenu,
                            QDialog, QFormLayout, QSpinBox, QCheckBox, QFileDialog, QSystemTrayIcon,
                            QSplitter, QTextEdit, QProgressBar, QDockWidget, QGroupBox)
from PyQt6.QtGui import QIcon, QPainter, QPen, QColor, QFont, QPalette, QGuiApplication, QAction
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QLocale, QTranslator
import pyqtgraph as pg
import numpy as np
from collections import defaultdict
import qdarkstyle
from typing import Dict, List, Tuple
import serial
import requests
import pickle
import sqlite3
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from scapy.all import sniff, IP, TCP, UDP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
DB_PATH = Path("portpainter.db")
def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            port INTEGER,
            protocol TEXT,
            local_ip TEXT,
            remote_ip TEXT,
            process_name TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_database()

# Translation setup
class Translator:
    def __init__(self):
        self.translators = {
            'en': QTranslator(),
            'fa': QTranslator(),
            'zh': QTranslator()
        }
        self.translations = {
            'en': {
                'app_name': 'PortPainter',
                'start_monitoring': 'Start Monitoring',
                'stop_monitoring': 'Stop Monitoring',
                'settings': 'Settings',
                'theme': 'Theme',
                'language': 'Language',
                'export': 'Export',
                'port': 'Port',
                'protocol': 'Protocol',
                'local_ip': 'Local IP',
                'remote_ip': 'Remote IP',
                'process': 'Process',
                'bytes_sent': 'Bytes Sent',
                'bytes_received': 'Bytes Received',
                'visualization': 'Visualization',
                'analytics': 'Analytics',
                'logs': 'Logs',
                'serial_ports': 'Serial Ports',
                'network_interfaces': 'Network Interfaces',
                'save_settings': 'Save Settings',
                'refresh_rate': 'Refresh Rate (ms)',
                'enable_alerts': 'Enable Alerts',
                'export_csv': 'Export to CSV',
                'export_image': 'Export Visualization as Image',
                'export_video': 'Export Visualization as Video',
                'clear_logs': 'Clear Logs',
                'about': 'About',
                'help': 'Help',
                'filter': 'Filter',
                'clear_filter': 'Clear Filter',
                'port_range': 'Port Range',
                'protocol_filter': 'Protocol Filter',
                'ip_filter': 'IP Filter',
                'process_filter': 'Process Filter',
                'pause_visualization': 'Pause Visualization',
                'resume_visualization': 'Resume Visualization',
                'zoom_in': 'Zoom In',
                'zoom_out': 'Zoom Out',
                'reset_view': 'Reset View',
                'advanced_settings': 'Advanced Settings',
                'threat_intelligence': 'Threat Intelligence',
                'enable_threat_intel': 'Enable Threat Intelligence',
                'api_key': 'API Key',
                'simulate_traffic': 'Simulate Traffic',
                'export_config': 'Export Configuration',
                'import_config': 'Import Configuration'
            },
            'fa': {
                'app_name': 'نقاش پورت',
                'start_monitoring': 'شروع نظارت',
                'stop_monitoring': 'توقف نظارت',
                'settings': 'تنظیمات',
                'theme': 'تم',
                'language': 'زبان',
                'export': 'صادر کردن',
                'port': 'پورت',
                'protocol': 'پروتکل',
                'local_ip': 'آی‌پی محلی',
                'remote_ip': 'آی‌پی راه دور',
                'process': 'فرآیند',
                'bytes_sent': 'بایت‌های ارسالی',
                'bytes_received': 'بایت‌های دریافتی',
                'visualization': 'تجسم',
                'analytics': 'تحلیل',
                'logs': 'لاگ‌ها',
                'serial_ports': 'پورت‌های سریال',
                'network_interfaces': 'رابط‌های شبکه',
                'save_settings': 'ذخیره تنظیمات',
                'refresh_rate': 'نرخ تازه‌سازی (میلی‌ثانیه)',
                'enable_alerts': 'فعال‌سازی هشدارها',
                'export_csv': 'صادر کردن به CSV',
                'export_image': 'صادر کردن تجسم به تصویر',
                'export_video': 'صادر کردن تجسم به ویدئو',
                'clear_logs': 'پاک کردن لاگ‌ها',
                'about': 'درباره',
                'help': 'راهنما',
                'filter': 'فیلتر',
                'clear_filter': 'پاک کردن فیلتر',
                'port_range': 'محدوده پورت',
                'protocol_filter': 'فیلتر پروتکل',
                'ip_filter': 'فیلتر آی‌پی',
                'process_filter': 'فیلتر فرآیند',
                'pause_visualization': 'مکث تجسم',
                'resume_visualization': 'از سرگیری تجسم',
                'zoom_in': 'بزرگنمایی',
                'zoom_out': 'کوچک‌نمایی',
                'reset_view': 'بازنشانی نما',
                'advanced_settings': 'تنظیمات پیشرفته',
                'threat_intelligence': 'هوش تهدید',
                'enable_threat_intel': 'فعال‌سازی هوش تهدید',
                'api_key': 'کلید API',
                'simulate_traffic': 'شبیه‌سازی ترافیک',
                'export_config': 'صادر کردن پیکربندی',
                'import_config': 'وارد کردن پیکربندی'
            },
            'zh': {
                'app_name': '端口画家',
                'start_monitoring': '开始监控',
                'stop_monitoring': '停止监控',
                'settings': '设置',
                'theme': '主题',
                'language': '语言',
                'export': '导出',
                'port': '端口',
                'protocol': '协议',
                'local_ip': '本地IP',
                'remote_ip': '远程IP',
                'process': '进程',
                'bytes_sent': '发送字节',
                'bytes_received': '接收字节',
                'visualization': '可视化',
                'analytics': '分析',
                'logs': '日志',
                'serial_ports': '串口',
                'network_interfaces': '网络接口',
                'save_settings': '保存设置',
                'refresh_rate': '刷新率（毫秒）',
                'enable_alerts': '启用警报',
                'export_csv': '导出到CSV',
                'export_image': '将可视化导出为图像',
                'export_video': '将可视化导出为视频',
                'clear_logs': '清除日志',
                'about': '关于',
                'help': '帮助',
                'filter': '过滤',
                'clear_filter': '清除过滤',
                'port_range': '端口范围',
                'protocol_filter': '协议过滤',
                'ip_filter': 'IP过滤',
                'process_filter': '进程过滤',
                'pause_visualization': '暂停可视化',
                'resume_visualization': '恢复可视化',
                'zoom_in': '放大',
                'zoom_out': '缩小',
                'reset_view': '重置视图',
                'advanced_settings': '高级设置',
                'threat_intelligence': '威胁情报',
                'enable_threat_intel': '启用威胁情报',
                'api_key': 'API密钥',
                'simulate_traffic': '模拟流量',
                'export_config': '导出配置',
                'import_config': '导入配置'
            }
        }

    def get_translation(self, language, key):
        return self.translations.get(language, self.translations['en']).get(key, key)

# Network and Serial Port Monitoring
class PortMonitor(QThread):
    data_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)

    def __init__(self, refresh_rate=1000):
        super().__init__()
        self.running = False
        self.refresh_rate = refresh_rate
        self.known_ports = set()
        self.serial_ports = []
        self.packet_queue = queue.Queue()
        self.threat_intel_enabled = False
        self.api_key = ''
        self.filter_port_min = 1
        self.filter_port_max = 65535
        self.filter_protocol = ''
        self.filter_ip = ''
        self.filter_process = ''

    def run(self):
        self.running = True
        packet_thread = threading.Thread(target=self.capture_packets)
        packet_thread.daemon = True
        packet_thread.start()

        while self.running:
            try:
                data = self.collect_data()
                self.data_signal.emit(data)
                self.check_alerts(data)
                time.sleep(self.refresh_rate / 1000)
            except Exception as e:
                logger.error(f"Error in PortMonitor: {e}")

    def capture_packets(self):
        def packet_callback(packet):
            if IP in packet and (TCP in packet or UDP in packet):
                self.packet_queue.put(packet)
        try:
            sniff(prn=packet_callback, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")

    def collect_data(self) -> Dict:
        data = {
            'network': [],
            'serial': [],
            'interfaces': [],
            'timestamp': datetime.now().isoformat()
        }

        # Network interfaces using psutil
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    data['interfaces'].append({
                        'interface': iface,
                        'address': addr.address,
                        'family': 'IPv4' if addr.family == socket.AF_INET else 'IPv6'
                    })

        # Network ports
        for conn in psutil.net_connections(kind='inet'):
            if not self.passes_filter(conn):
                continue
            process = None
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
            except psutil.NoSuchProcess:
                pass
            data['network'].append({
                'port': conn.laddr.port,
                'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'local_ip': conn.laddr.ip,
                'remote_ip': conn.raddr.ip if conn.raddr else '',
                'process_name': process.name() if process else 'Unknown',
                'bytes_sent': process.io_counters().write_bytes if process else 0,
                'bytes_received': process.io_counters().read_bytes if process else 0,
                'status': conn.status
            })

        # Serial ports (fallback if serial.tools.list_ports fails)
        data['serial'].append({
            'port': 'N/A',
            'description': 'Serial port listing not available',
            'status': 'Error',
            'baudrate': 0
        })

        # Process packet queue
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            if TCP in packet:
                data['network'].append({
                    'port': packet[TCP].dport,
                    'protocol': 'TCP',
                    'local_ip': packet[IP].dst,
                    'remote_ip': packet[IP].src,
                    'process_name': 'Unknown',
                    'bytes_sent': len(packet),
                    'bytes_received': 0,
                    'status': 'N/A'
                })

        return data

    def passes_filter(self, conn):
        if conn.laddr.port < self.filter_port_min or conn.laddr.port > self.filter_port_max:
            return False
        if self.filter_protocol and conn.type != {'TCP': socket.SOCK_STREAM, 'UDP': socket.SOCK_DGRAM}.get(self.filter_protocol):
            return False
        if self.filter_ip and self.filter_ip not in (conn.laddr.ip, conn.raddr.ip if conn.raddr else ''):
            return False
        if self.filter_process:
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                if process and self.filter_process.lower() not in process.name().lower():
                    return False
            except psutil.NoSuchProcess:
                return False
        return True

    def check_alerts(self, data):
        current_ports = {item['port'] for item in data['network']}
        new_ports = current_ports - self.known_ports
        closed_ports = self.known_ports - current_ports
        self.known_ports = current_ports

        for port in new_ports:
            self.alert_signal.emit(f"New port opened: {port}")
            if self.threat_intel_enabled:
                self.check_threat_intel(port)
        for port in closed_ports:
            self.alert_signal.emit(f"Port closed: {port}")

    def check_threat_intel(self, port):
        try:
            response = requests.get(
                f"https://api.threatintel.example/check?port={port}&key={self.api_key}",
                timeout=5
            )
            if response.status_code == 200 and response.json().get('threat'):
                self.alert_signal.emit(f"Threat detected on port {port}: {response.json()['details']}")
        except requests.RequestException as e:
            logger.error(f"Threat intelligence error: {e}")

    def set_filters(self, port_min, port_max, protocol, ip, process):
        self.filter_port_min = port_min
        self.filter_port_max = port_max
        self.filter_protocol = protocol
        self.filter_ip = ip
        self.filter_process = process

    def set_threat_intel(self, enabled, api_key):
        self.threat_intel_enabled = enabled
        self.api_key = api_key

    def stop(self):
        self.running = False
        self.wait()

# Visualization Widget
class VisualizationWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.port_data = defaultdict(list)
        self.paused = False
        self.zoom_level = 1.0
        self.init_ui()
        self.colors = {
            'TCP': Qt.GlobalColor.blue,
            'UDP': Qt.GlobalColor.green,
            'Alert': Qt.GlobalColor.red
        }
        self.animations = []

    def init_ui(self):
        layout = QVBoxLayout()
        self.figure = plt.Figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Toolbar for visualization controls
        toolbar = QToolBar()
        pause_action = QAction('Pause', self)
        pause_action.triggered.connect(self.toggle_pause)
        toolbar.addAction(pause_action)
        zoom_in_action = QAction('Zoom In', self)
        zoom_in_action.triggered.connect(self.zoom_in)
        toolbar.addAction(zoom_in_action)
        zoom_out_action = QAction('Zoom Out', self)
        zoom_out_action.triggered.connect(self.zoom_out)
        toolbar.addAction(zoom_out_action)
        reset_action = QAction('Reset View', self)
        reset_action.triggered.connect(self.reset_view)
        toolbar.addAction(reset_action)
        layout.addWidget(toolbar)

        self.setLayout(layout)

    def update_visualization(self, data):
        if self.paused:
            return
        self.port_data['network'].append(data['network'])
        if len(self.port_data['network']) > 100:
            self.port_data['network'].pop(0)

        self.figure.clear()
        ax = self.figure.add_subplot(111, projection='3d' if self.zoom_level > 1.5 else None)
        for item in data['network']:
            # Corrected scatter call with proper argument names
            if ax.name == '3d':
                ax.scatter(
                    x=item['port'],
                    y=item['bytes_sent'] + item['bytes_received'],
                    z=item['bytes_sent'],
                    c='blue' if item['protocol'] == 'TCP' else 'green',
                    alpha=0.5,
                    s=50 * self.zoom_level
                )
            else:
                ax.scatter(
                    x=item['port'],
                    y=item['bytes_sent'] + item['bytes_received'],
                    c='blue' if item['protocol'] == 'TCP' else 'green',
                    alpha=0.5,
                    s=50 * self.zoom_level
                )
        ax.set_xlabel('Port Number')
        ax.set_ylabel('Bytes Transferred')
        if ax.name == '3d':
            ax.set_zlabel('Bytes Sent')
        ax.set_title('Network Port Activity')
        self.canvas.draw()

    def toggle_pause(self):
        self.paused = not self.paused
        self.sender().setText('Resume' if self.paused else 'Pause')

    def zoom_in(self):
        self.zoom_level *= 1.2
        self.update_visualization(self.port_data['network'][-1] if self.port_data['network'] else {})

    def zoom_out(self):
        self.zoom_level /= 1.2
        if self.zoom_level < 0.5:
            self.zoom_level = 0.5
        self.update_visualization(self.port_data['network'][-1] if self.port_data['network'] else {})

    def reset_view(self):
        self.zoom_level = 1.0
        self.update_visualization(self.port_data['network'][-1] if self.port_data['network'] else {})

# Analytics Widget
class AnalyticsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.plot_widget = pg.PlotWidget()
        layout.addWidget(self.plot_widget)
        self.setLayout(layout)

    def update_analytics(self, data):
        ports = defaultdict(int)
        for item in data['network']:
            ports[item['port']] += item['bytes_sent'] + item['bytes_received']
        
        x = sorted(ports.keys())
        y = [ports[port] for port in x]
        
        self.plot_widget.clear()
        self.plot_widget.plot(x, y, pen=pg.mkPen('b', width=2))
        self.plot_widget.setLabel('bottom', 'Port')
        self.plot_widget.setLabel('left', 'Bytes')

# Filter Widget
class FilterWidget(QDockWidget):
    def __init__(self, parent, translator, language):
        super().__init__(translator.get_translation(language, 'filter'), parent)
        self.translator = translator
        self.language = language
        self.init_ui()

    def init_ui(self):
        widget = QWidget()
        layout = QFormLayout()

        self.port_min = QSpinBox()
        self.port_min.setRange(1, 65535)
        self.port_min.setValue(1)
        layout.addRow(self.translator.get_translation(self.language, 'port_range'), self.port_min)

        self.port_max = QSpinBox()
        self.port_max.setRange(1, 65535)
        self.port_max.setValue(65535)
        layout.addRow('', self.port_max)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(['All', 'TCP', 'UDP'])
        layout.addRow(self.translator.get_translation(self.language, 'protocol_filter'), self.protocol_combo)

        self.ip_filter = QLineEdit()
        layout.addRow(self.translator.get_translation(self.language, 'ip_filter'), self.ip_filter)

        self.process_filter = QLineEdit()
        layout.addRow(self.translator.get_translation(self.language, 'process_filter'), self.process_filter)

        apply_button = QPushButton(self.translator.get_translation(self.language, 'filter'))
        apply_button.clicked.connect(self.apply_filter)
        layout.addWidget(apply_button)

        clear_button = QPushButton(self.translator.get_translation(self.language, 'clear_filter'))
        clear_button.clicked.connect(self.clear_filter)
        layout.addWidget(clear_button)

        widget.setLayout(layout)
        self.setWidget(widget)

    def apply_filter(self):
        self.parent().monitor_thread.set_filters(
            self.port_min.value(),
            self.port_max.value(),
            self.protocol_combo.currentText() if self.protocol_combo.currentText() != 'All' else '',
            self.ip_filter.text(),
            self.process_filter.text()
        )

    def clear_filter(self):
        self.port_min.setValue(1)
        self.port_max.setValue(65535)
        self.protocol_combo.setCurrentText('All')
        self.ip_filter.clear()
        self.process_filter.clear()
        self.apply_filter()

# Main Application Window
class PortPainterWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.translator = Translator()
        self.current_language = 'en'
        self.current_theme = 'windows11'
        self.refresh_rate = 1000
        self.alerts_enabled = True
        self.threat_intel_enabled = False
        self.threat_intel_api_key = ''
        self.monitor_thread = PortMonitor(self.refresh_rate)
        self.monitor_thread.data_signal.connect(self.update_ui)
        self.monitor_thread.alert_signal.connect(self.show_alert)
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        self.setWindowTitle(self.translator.get_translation(self.current_language, 'app_name'))
        self.setGeometry(100, 100, 1200, 800)
        
        # Set window icon and favicon
        icon_path = 'PortPainter.jpg'
        if Path(icon_path).exists():
            self.setWindowIcon(QIcon(icon_path))
            # Note: Favicon is typically set in web applications, not desktop apps
            # For desktop apps, the window icon serves as the equivalent
        else:
            logger.warning("Icon file 'PortPainter.jpg' not found")

        # Menu Bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu(self.translator.get_translation(self.current_language, 'file'))
        settings_action = QAction(self.translator.get_translation(self.current_language, 'settings'), self)
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        
        export_menu = file_menu.addMenu(self.translator.get_translation(self.current_language, 'export'))
        export_csv_action = QAction(self.translator.get_translation(self.current_language, 'export_csv'), self)
        export_csv_action.triggered.connect(self.export_to_csv)
        export_menu.addAction(export_csv_action)
        export_image_action = QAction(self.translator.get_translation(self.current_language, 'export_image'), self)
        export_image_action.triggered.connect(self.export_visualization)
        export_menu.addAction(export_image_action)
        export_video_action = QAction(self.translator.get_translation(self.current_language, 'export_video'), self)
        export_video_action.triggered.connect(self.export_video)
        export_menu.addAction(export_video_action)
        export_config_action = QAction(self.translator.get_translation(self.current_language, 'export_config'), self)
        export_config_action.triggered.connect(self.export_config)
        export_menu.addAction(export_config_action)
        import_config_action = QAction(self.translator.get_translation(self.current_language, 'import_config'), self)
        import_config_action.triggered.connect(self.import_config)
        export_menu.addAction(import_config_action)

        help_menu = menubar.addMenu(self.translator.get_translation(self.current_language, 'help'))
        about_action = QAction(self.translator.get_translation(self.current_language, 'about'), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        # Toolbar
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        start_action = QAction(self.translator.get_translation(self.current_language, 'start_monitoring'), self)
        start_action.triggered.connect(self.start_monitoring)
        toolbar.addAction(start_action)
        stop_action = QAction(self.translator.get_translation(self.current_language, 'stop_monitoring'), self)
        stop_action.triggered.connect(self.stop_monitoring)
        toolbar.addAction(stop_action)
        simulate_action = QAction(self.translator.get_translation(self.current_language, 'simulate_traffic'), self)
        simulate_action.triggered.connect(self.simulate_traffic)
        toolbar.addAction(simulate_action)

        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)

        # Visualization Tab
        vis_widget = VisualizationWidget()
        tabs.addTab(vis_widget, self.translator.get_translation(self.current_language, 'visualization'))
        self.vis_widget = vis_widget

        # Analytics Tab
        analytics_widget = AnalyticsWidget()
        tabs.addTab(analytics_widget, self.translator.get_translation(self.current_language, 'analytics'))
        self.analytics_widget = analytics_widget

        # Ports Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            self.translator.get_translation(self.current_language, 'port'),
            self.translator.get_translation(self.current_language, 'protocol'),
            self.translator.get_translation(self.current_language, 'local_ip'),
            self.translator.get_translation(self.current_language, 'remote_ip'),
            self.translator.get_translation(self.current_language, 'process'),
            self.translator.get_translation(self.current_language, 'bytes_sent'),
            self.translator.get_translation(self.current_language, 'bytes_received'),
            'Status'
        ])
        tabs.addTab(self.table, self.translator.get_translation(self.current_language, 'network_interfaces'))

        # Serial Ports Table
        self.serial_table = QTableWidget()
        self.serial_table.setColumnCount(4)
        self.serial_table.setHorizontalHeaderLabels([
            self.translator.get_translation(self.current_language, 'port'),
            'Description',
            'Status',
            'Baudrate'
        ])
        tabs.addTab(self.serial_table, self.translator.get_translation(self.current_language, 'serial_ports'))

        # Logs
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        tabs.addTab(self.log_text, self.translator.get_translation(self.current_language, 'logs'))

        # Filter Dock
        self.filter_dock = FilterWidget(self, self.translator, self.current_language)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.filter_dock)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready')

        # System Tray
        if Path(icon_path).exists():
            self.tray_icon = QSystemTrayIcon(QIcon(icon_path), self)
            tray_menu = QMenu()
            restore_action = QAction('Restore', self)
            restore_action.triggered.connect(self.show)
            tray_menu.addAction(restore_action)
            quit_action = QAction('Quit', self)
            quit_action.triggered.connect(QApplication.quit)
            tray_menu.addAction(quit_action)
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
        else:
            logger.warning("System tray icon not set: 'PortPainter.jpg' not found")
            self.tray_icon = None

        # Apply theme
        self.apply_theme()

    def apply_theme(self):
        if self.current_theme == 'windows11':
            app.setStyle('Fusion')
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            app.setPalette(palette)
        elif self.current_theme == 'dark':
            app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt6'))
        elif self.current_theme == 'red_blue':
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(50, 50, 100))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 70))
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Button, QColor(100, 50, 50))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
            app.setPalette(palette)
        else:  # Default Windows
            app.setStyle('Windows')

        # Adjust text direction based on language
        if self.current_language == 'fa':
            self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        else:
            self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

    def update_ui(self, data):
        # Update table
        self.table.setRowCount(len(data['network']))
        for i, item in enumerate(data['network']):
            self.table.setItem(i, 0, QTableWidgetItem(str(item['port'])))
            self.table.setItem(i, 1, QTableWidgetItem(item['protocol']))
            self.table.setItem(i, 2, QTableWidgetItem(item['local_ip']))
            self.table.setItem(i, 3, QTableWidgetItem(item['remote_ip']))
            self.table.setItem(i, 4, QTableWidgetItem(item['process_name']))
            self.table.setItem(i, 5, QTableWidgetItem(str(item['bytes_sent'])))
            self.table.setItem(i, 6, QTableWidgetItem(str(item['bytes_received'])))
            self.table.setItem(i, 7, QTableWidgetItem(item['status']))

        # Update serial table
        self.serial_table.setRowCount(len(data['serial']))
        for i, item in enumerate(data['serial']):
            self.serial_table.setItem(i, 0, QTableWidgetItem(item['port']))
            self.serial_table.setItem(i, 1, QTableWidgetItem(item['description']))
            self.serial_table.setItem(i, 2, QTableWidgetItem(item['status']))
            self.serial_table.setItem(i, 3, QTableWidgetItem(str(item['baudrate'])))

        # Update visualization
        try:
            self.vis_widget.update_visualization(data)
        except Exception as e:
            logger.error(f"Visualization update error: {e}")

        self.analytics_widget.update_analytics(data)

        # Log data
        self.log_text.append(f"{data['timestamp']}: {len(data['network'])} network ports, {len(data['serial'])} serial ports")

        # Save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for item in data['network']:
            cursor.execute('''
                INSERT INTO port_activity (timestamp, port, protocol, local_ip, remote_ip, process_name, bytes_sent, bytes_received)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['timestamp'], item['port'], item['protocol'], item['local_ip'],
                item['remote_ip'], item['process_name'], item['bytes_sent'], item['bytes_received']
            ))
        conn.commit()
        conn.close()

    def show_alert(self, message):
        if self.alerts_enabled:
            if self.tray_icon:
                self.tray_icon.showMessage(
                    self.translator.get_translation(self.current_language, 'app_name'),
                    message,
                    QSystemTrayIcon.MessageIcon.Warning
                )
            self.log_text.append(f"ALERT: {message}")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO alerts (timestamp, message) VALUES (?, ?)', (datetime.now().isoformat(), message))
            conn.commit()
            conn.close()

    def start_monitoring(self):
        if not self.monitor_thread.isRunning():
            self.monitor_thread.start()
            self.status_bar.showMessage(self.translator.get_translation(self.current_language, 'start_monitoring'))

    def stop_monitoring(self):
        self.monitor_thread.stop()
        self.status_bar.showMessage(self.translator.get_translation(self.current_language, 'stop_monitoring'))

    def simulate_traffic(self):
        # Simulate network traffic
        data = {
            'network': [
                {
                    'port': np.random.randint(1, 65535),
                    'protocol': np.random.choice(['TCP', 'UDP']),
                    'local_ip': '127.0.0.1',
                    'remote_ip': f"192.168.1.{np.random.randint(1, 255)}",
                    'process_name': 'simulated_process',
                    'bytes_sent': np.random.randint(100, 10000),
                    'bytes_received': np.random.randint(100, 10000),
                    'status': 'ESTABLISHED'
                } for _ in range(5)
            ],
            'serial': [],
            'timestamp': datetime.now().isoformat()
        }
        self.update_ui(data)
        self.show_alert("Simulated traffic generated")

    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.translator.get_translation(self.current_language, 'settings'))
        layout = QFormLayout()

        # Basic Settings
        basic_group = QGroupBox(self.translator.get_translation(self.current_language, 'settings'))
        basic_layout = QFormLayout()

        theme_combo = QComboBox()
        theme_combo.addItems(['windows11', 'dark', 'red_blue', 'default'])
        theme_combo.setCurrentText(self.current_theme)
        basic_layout.addRow(self.translator.get_translation(self.current_language, 'theme'), theme_combo)

        lang_combo = QComboBox()
        lang_combo.addItems(['English', 'فارسی', '中文'])
        lang_combo.setCurrentText({'en': 'English', 'fa': 'فارسی', 'zh': '中文'}[self.current_language])
        basic_layout.addRow(self.translator.get_translation(self.current_language, 'language'), lang_combo)

        refresh_spin = QSpinBox()
        refresh_spin.setRange(100, 10000)
        refresh_spin.setValue(self.refresh_rate)
        basic_layout.addRow(self.translator.get_translation(self.current_language, 'refresh_rate'), refresh_spin)

        alerts_check = QCheckBox()
        alerts_check.setChecked(self.alerts_enabled)
        basic_layout.addRow(self.translator.get_translation(self.current_language, 'enable_alerts'), alerts_check)

        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)

        # Advanced Settings
        advanced_group = QGroupBox(self.translator.get_translation(self.current_language, 'advanced_settings'))
        advanced_layout = QFormLayout()

        threat_intel_check = QCheckBox()
        threat_intel_check.setChecked(self.threat_intel_enabled)
        advanced_layout.addRow(self.translator.get_translation(self.current_language, 'enable_threat_intel'), threat_intel_check)

        api_key_input = QLineEdit()
        api_key_input.setText(self.threat_intel_api_key)
        api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        advanced_layout.addRow(self.translator.get_translation(self.current_language, 'api_key'), api_key_input)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        save_button = QPushButton(self.translator.get_translation(self.current_language, 'save_settings'))
        save_button.clicked.connect(lambda: self.save_settings(
            theme_combo.currentText(),
            {'English': 'en', 'فارسی': 'fa', '中文': 'zh'}[lang_combo.currentText()],
            refresh_spin.value(),
            alerts_check.isChecked(),
            threat_intel_check.isChecked(),
            api_key_input.text()
        ))
        layout.addWidget(save_button)

        dialog.setLayout(layout)
        dialog.exec()

    def save_settings(self, theme, language, refresh_rate, alerts_enabled, threat_intel_enabled, api_key):
        self.current_theme = theme
        self.current_language = language
        self.refresh_rate = refresh_rate
        self.alerts_enabled = alerts_enabled
        self.threat_intel_enabled = threat_intel_enabled
        self.threat_intel_api_key = api_key
        self.monitor_thread.refresh_rate = refresh_rate
        self.monitor_thread.set_threat_intel(threat_intel_enabled, api_key)
        self.apply_theme()

        # Save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('theme', theme))
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('language', language))
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('refresh_rate', str(refresh_rate)))
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('alerts_enabled', str(alerts_enabled)))
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('threat_intel_enabled', str(threat_intel_enabled)))
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('api_key', api_key))
        conn.commit()
        conn.close()

        self.update_ui_texts()

    def load_settings(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        settings = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()

        self.current_theme = settings.get('theme', 'windows11')
        self.current_language = settings.get('language', 'en')
        self.refresh_rate = int(settings.get('refresh_rate', '1000'))
        self.alerts_enabled = settings.get('alerts_enabled', 'True') == 'True'
        self.threat_intel_enabled = settings.get('threat_intel_enabled', 'False') == 'True'
        self.threat_intel_api_key = settings.get('api_key', '')
        self.monitor_thread.refresh_rate = self.refresh_rate
        self.monitor_thread.set_threat_intel(self.threat_intel_enabled, self.threat_intel_api_key)
        self.apply_theme()
        self.update_ui_texts()

    def update_ui_texts(self):
        self.setWindowTitle(self.translator.get_translation(self.current_language, 'app_name'))
        self.menuBar().clear()
        file_menu = self.menuBar().addMenu(self.translator.get_translation(self.current_language, 'file'))
        settings_action = QAction(self.translator.get_translation(self.current_language, 'settings'), self)
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        export_menu = file_menu.addMenu(self.translator.get_translation(self.current_language, 'export'))
        export_csv_action = QAction(self.translator.get_translation(self.current_language, 'export_csv'), self)
        export_csv_action.triggered.connect(self.export_to_csv)
        export_menu.addAction(export_csv_action)
        export_image_action = QAction(self.translator.get_translation(self.current_language, 'export_image'), self)
        export_image_action.triggered.connect(self.export_visualization)
        export_menu.addAction(export_image_action)
        export_video_action = QAction(self.translator.get_translation(self.current_language, 'export_video'), self)
        export_video_action.triggered.connect(self.export_video)
        export_menu.addAction(export_video_action)
        export_config_action = QAction(self.translator.get_translation(self.current_language, 'export_config'), self)
        export_config_action.triggered.connect(self.export_config)
        export_menu.addAction(export_config_action)
        import_config_action = QAction(self.translator.get_translation(self.current_language, 'import_config'), self)
        import_config_action.triggered.connect(self.import_config)
        export_menu.addAction(import_config_action)
        help_menu = self.menuBar().addMenu(self.translator.get_translation(self.current_language, 'help'))
        about_action = QAction(self.translator.get_translation(self.current_language, 'about'), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        self.table.setHorizontalHeaderLabels([
            self.translator.get_translation(self.current_language, 'port'),
            self.translator.get_translation(self.current_language, 'protocol'),
            self.translator.get_translation(self.current_language, 'local_ip'),
            self.translator.get_translation(self.current_language, 'remote_ip'),
            self.translator.get_translation(self.current_language, 'process'),
            self.translator.get_translation(self.current_language, 'bytes_sent'),
            self.translator.get_translation(self.current_language, 'bytes_received'),
            'Status'
        ])
        self.serial_table.setHorizontalHeaderLabels([
            self.translator.get_translation(self.current_language, 'port'),
            'Description',
            'Status',
            'Baudrate'
        ])
        self.filter_dock.setWindowTitle(self.translator.get_translation(self.current_language, 'filter'))

    def export_to_csv(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save CSV', '', 'CSV Files (*.csv)')
        if filename:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM port_activity')
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('Timestamp,Port,Protocol,Local IP,Remote IP,Process,Bytes Sent,Bytes Received\n')
                for row in cursor.fetchall():
                    f.write(','.join(map(str, row[1:])) + '\n')
            conn.close()

    def export_visualization(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Image', '', 'PNG Files (*.png)')
        if filename:
            self.vis_widget.canvas.figure.savefig(filename)

    def export_video(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Video', '', 'MP4 Files (*.mp4)')
        if filename:
            self.status_bar.showMessage('Video export not implemented in this version')

    def export_config(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Config', '', 'JSON Files (*.json)')
        if filename:
            config = {
                'theme': self.current_theme,
                'language': self.current_language,
                'refresh_rate': self.refresh_rate,
                'alerts_enabled': self.alerts_enabled,
                'threat_intel_enabled': self.threat_intel_enabled,
                'api_key': self.threat_intel_api_key
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f)

    def import_config(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open Config', '', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'r', encoding='utf-8') as f:
                config = json.load(f)
            self.save_settings(
                config.get('theme', 'windows11'),
                config.get('language', 'en'),
                config.get('refresh_rate', 1000),
                config.get('alerts_enabled', True),
                config.get('threat_intel_enabled', False),
                config.get('api_key', '')
            )

    def show_about(self):
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle(self.translator.get_translation(self.current_language, 'about'))
        layout = QVBoxLayout()
        layout.addWidget(QLabel('PortPainter v1.0\nA network and serial port monitoring tool\nDeveloped with PyQt6'))
        about_dialog.setLayout(layout)
        about_dialog.exec()

    def closeEvent(self, event):
        self.monitor_thread.stop()
        event.accept()

async def main():
    global app
    app = QApplication(sys.argv)
    window = PortPainterWindow()
    window.show()

    if platform.system() == "Emscripten":
        await asyncio.sleep(1.0 / 60)
    else:
        sys.exit(app.exec())

if __name__ == '__main__':
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())