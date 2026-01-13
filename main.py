import psycopg2
import winreg  
from PyQt6.QtWidgets import QApplication, QTableWidgetItem, QHeaderView, QMessageBox
from PyQt6 import uic
from PyQt6.QtGui import QColor
import requests
from PyQt6.QtCore import QThread, pyqtSignal
import urllib.parse
import time
from settings import db_params, api_key

Form, Windows = uic.loadUiType('graf.ui')

win = QApplication([])
windows = Windows()
form = Form()
form.setupUi(windows)

def get_installed_software():
    software_list = []
    
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"), 
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"), 
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") 
    ]
    
    for root, path in paths:
        try:
            reg_key = winreg.OpenKey(root, path)
            num_subkeys = winreg.QueryInfoKey(reg_key)[0]
            
            for i in range(num_subkeys):
                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    subkey = winreg.OpenKey(reg_key, subkey_name)
                    
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        
                        if any(name == s[0] for s in software_list):
                            continue
                            
                        try:
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except FileNotFoundError:
                            version = "-"
                            
                        try:
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except FileNotFoundError:
                            publisher = "-"
                        
                        if name:
                            software_list.append((name, version, publisher))
                            
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                except Exception:
                    continue
            winreg.CloseKey(reg_key)
        except Exception:
            continue 
            
    return software_list

def save_software_to_db(software_list):
    try:
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()
        
        for name, version, vendor in software_list:
            query = """
            insert into software_inventory (display_name, software_version, vendor)
            values (%s, %s, %s)
            on conflict do nothing;
            """
            cursor.execute(query, (name, version, vendor))
            
        conn.commit()
        cursor.close()
        conn.close()
        print("Данные успешно сохранены в базу и сопоставлены с CVE.")
    except Exception as e:
        print(f"Ошибка базы данных: {e}")

def load_dashboard_data():
    try:
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()
        
        cursor.execute("select soft_name, version, cve_id, risk_level, risk_score from security_dashboard_v")
        rows = cursor.fetchall()
        
        form.table_dashboard.setRowCount(len(rows))
        form.table_dashboard.setColumnCount(5)
        form.table_dashboard.setHorizontalHeaderLabels(["ПО", "Версия", "CVE ID", "Уровень", "Score"])
        form.table_dashboard.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        for i, (name, ver, cve, level, score) in enumerate(rows):
            form.table_dashboard.setItem(i, 0, QTableWidgetItem(str(name)))
            form.table_dashboard.setItem(i, 1, QTableWidgetItem(str(ver)))
            form.table_dashboard.setItem(i, 2, QTableWidgetItem(str(cve)))
            
            level_item = QTableWidgetItem(str(level))
            if level == 'critical':
                level_item.setBackground(QColor(255, 100, 100))
            elif level == 'high':
                level_item.setBackground(QColor(255, 180, 100))
            
            form.table_dashboard.setItem(i, 3, level_item)
            form.table_dashboard.setItem(i, 4, QTableWidgetItem(str(score)))
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка при обновлении дашборда: {e}")

def action_scan_pc():
    print("Начинаю сканирование...")
    data = get_installed_software()
    
    form.table_software.setRowCount(len(data))
    form.table_software.setColumnCount(3)
    form.table_software.setHorizontalHeaderLabels(["Название ПО", "Версия", "Вендор"])
    form.table_software.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    
    for row_idx, (name, version, publisher) in enumerate(data):
        form.table_software.setItem(row_idx, 0, QTableWidgetItem(str(name)))
        form.table_software.setItem(row_idx, 1, QTableWidgetItem(str(version)))
        form.table_software.setItem(row_idx, 2, QTableWidgetItem(str(publisher)))
    
    save_software_to_db(data)
    load_dashboard_data()
    print(f"Готово. Найдено {len(data)} программ.")

worker = None 

def on_update_finished():
    print("Обновление завершено!")
    load_dashboard_data()
    load_vulnerabilities_to_table()
    form.btn_add_cve.setEnabled(True)
    form.btn_add_cve.setText("Добавить")

def update_progress_label(text):
    print(text)
    form.btn_add_cve.setText(text)

def fetch_and_save_cve():
    global worker
    form.btn_add_cve.setEnabled(False) 
    worker = UpdateWorker()
    worker.progress.connect(update_progress_label)
    worker.finished.connect(on_update_finished)
    worker.start()

def show_details():
    item = form.table_vulnerabilities.currentItem()
    if item:
        row = form.table_vulnerabilities.currentRow()
        description = form.table_vulnerabilities.item(row, 1).text()
        form.txt_details_cve.setPlainText(description)

def load_vulnerabilities_to_table():
    try:
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()
        
        cursor.execute("select cve_id, description, cvss_score, severity_level from vulnerabilities order by cvss_score desc")
        rows = cursor.fetchall()
        
        form.table_vulnerabilities.setRowCount(len(rows))
        form.table_vulnerabilities.setColumnCount(4)
        form.table_vulnerabilities.setHorizontalHeaderLabels(["CVE ID", "Описание", "Score", "Уровень"])
        form.table_vulnerabilities.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        for i, (cve_id, desc, score, level) in enumerate(rows):
            form.table_vulnerabilities.setItem(i, 0, QTableWidgetItem(str(cve_id)))
            form.table_vulnerabilities.setItem(i, 1, QTableWidgetItem(str(desc)))
            form.table_vulnerabilities.setItem(i, 2, QTableWidgetItem(str(score)))
            form.table_vulnerabilities.setItem(i, 3, QTableWidgetItem(str(level)))
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Ошибка при заполнении таблицы уязвимостей: {e}")

class UpdateWorker(QThread):
    progress = pyqtSignal(str) 
    finished = pyqtSignal()    

    def run(self):
        headers = {"apiKey": api_key}
        try:
            conn = psycopg2.connect(**db_params)
            cursor = conn.cursor()
            
            cursor.execute("select distinct display_name from software_inventory")
            software_list = cursor.fetchall()

            total = len(software_list)
            for index, (name,) in enumerate(software_list):
                words = name.split()
                search_term = f"{words[0]} {words[1]}" if len(words) > 1 else name
                encoded_term = urllib.parse.quote(search_term)
                
                self.progress.emit(f"[{index+1}/{total}] Поиск: {search_term}...")
                time.sleep(0.6) 

                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_term}&resultsPerPage=20"
                
                try:
                    response = requests.get(url, headers=headers, timeout=10) 
                    
                    if response.status_code == 200:
                        data = response.json()
                        items = data.get('vulnerabilities', [])
                        
                        for item in items:
                            cve_data = item.get('cve', {})
                            cve_id = cve_data.get('id')
                            descriptions = cve_data.get('descriptions', [])
                            desc_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description")
                            
                            metrics = cve_data.get('metrics', {})
                            cvss_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                            score = cvss_data[0]['cvssData']['baseScore'] if cvss_data else 0.0

                            cursor.execute("""
                                insert into vulnerabilities (cve_id, description, cvss_score)
                                values (%s, %s, %s)
                                on conflict (cve_id) do nothing;
                            """, (cve_id, desc_text, score))
                        
                        conn.commit() 
                    elif response.status_code == 403:
                        self.progress.emit("Ошибка 403: Проверьте ключ или увеличьте паузу")
                except Exception as req_err:
                    print(f"Ошибка сети для {name}: {req_err}")
            
            cursor.close()
            conn.close()
            self.finished.emit()
            
        except Exception as e:
            print(f"Критическая ошибка потока: {e}")
        finally:
            self.finished.emit()

def filter_table(table_widget, search_text):
    search_text = search_text.lower()
    for row in range(table_widget.rowCount()):
        match = False
        for col in range(table_widget.columnCount()):
            item = table_widget.item(row, col)
            if item and search_text in item.text().lower():
                match = True
                break
        table_widget.setRowHidden(row, not match)

def reset_table_filter(table_widget, search_line):
    search_line.clear()
    for row in range(table_widget.rowCount()):
        table_widget.setRowHidden(row, False)

def search_software():
    filter_table(form.table_software, form.search_line.text())

def reset_software():
    reset_table_filter(form.table_software, form.search_line)

def search_cve():
    filter_table(form.table_vulnerabilities, form.search_line_3.text())

def reset_cve():
    reset_table_filter(form.table_vulnerabilities, form.search_line_3)

def search_dashboard():
    filter_table(form.table_dashboard, form.search_line_2.text())

def reset_dashboard():
    reset_table_filter(form.table_dashboard, form.search_line_2)

def clear_software_db():
    reply = QMessageBox.question(None, 'Подтверждение', 
                                 "Вы уверены? Это удалит всё найденное ПО из базы.",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    
    if reply == QMessageBox.StandardButton.Yes:
        try:
            conn = psycopg2.connect(**db_params)
            cursor = conn.cursor()
            cursor.execute("truncate table software_inventory restart identity cascade;") 
            conn.commit()
            cursor.close()
            conn.close()
            
            form.table_software.setRowCount(0)
            print("Таблица ПО очищена.")
            load_dashboard_data()
        except Exception as e:
            print(f"Ошибка очистки ПО: {e}")

def clear_cve_db():
    reply = QMessageBox.question(None, 'Подтверждение', 
                                 "Вы уверены? Это удалит базу уязвимостей.",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    
    if reply == QMessageBox.StandardButton.Yes:
        try:
            conn = psycopg2.connect(**db_params)
            cursor = conn.cursor()
            cursor.execute("truncate table vulnerabilities restart identity cascade;")
            conn.commit()
            cursor.close()
            conn.close()
            
            form.table_vulnerabilities.setRowCount(0)
            form.txt_details_cve.clear()
            print("Таблица CVE очищена.")
            load_dashboard_data()
        except Exception as e:
            print(f"Ошибка очистки CVE: {e}")

form.table_vulnerabilities.itemClicked.connect(show_details)
form.btn_add_cve.clicked.connect(fetch_and_save_cve)
form.btn_add_soft.clicked.connect(action_scan_pc) 
form.btn_refresh_dashboard.clicked.connect(load_dashboard_data) 
form.search_btn.clicked.connect(search_software)
form.reset_btn_2.clicked.connect(reset_software)
form.search_btn_3.clicked.connect(search_cve)
form.reset_btn.clicked.connect(reset_cve)
form.search_btn_2.clicked.connect(search_dashboard)
form.reset_btn_3.clicked.connect(reset_dashboard)
form.btn_delete_soft.clicked.connect(clear_software_db)
form.btn_delete_cve.clicked.connect(clear_cve_db)

load_vulnerabilities_to_table()
windows.show()
win.exec()