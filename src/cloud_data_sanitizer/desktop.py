from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cloud_data_sanitizer.i18n import SUPPORTED_LOCALES, Translator, get_translator
from cloud_data_sanitizer.keystore import MemoryKeyStore, OSKeyStore
from cloud_data_sanitizer.models import SanitizerError
from cloud_data_sanitizer.service import inspect_dataset, sanitize_dataset

PREFS_NAME = ".cloud-data-sanitizer-prefs.json"


def _prefs_path() -> Path:
    return Path.home() / PREFS_NAME


def _load_locale_pref() -> str:
    path = _prefs_path()
    if not path.is_file():
        return "en-US"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return str(payload.get("locale", "en-US"))
    except (OSError, json.JSONDecodeError, TypeError):
        return "en-US"


def _save_locale_pref(locale: str) -> None:
    path = _prefs_path()
    path.write_text(json.dumps({"locale": locale}, indent=2), encoding="utf-8")


class SanitizerWindow(QMainWindow):
    def __init__(self, translator: Translator) -> None:
        super().__init__()
        self.tr_ = translator
        self.input_path: Path | None = None
        self.sheet_name: str | None = None
        self.columns: list[dict[str, Any]] = []
        self.resize(980, 700)
        self.setMinimumSize(760, 560)
        self._build_ui()
        self._retranslate()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        self.title = QLabel()
        self.title.setObjectName("title")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("muted")
        title_box.addWidget(self.title)
        title_box.addWidget(self.subtitle)
        heading.addLayout(title_box)
        heading.addStretch()

        lang_box = QHBoxLayout()
        self.lang_label = QLabel()
        self.lang_combo = QComboBox()
        for locale in SUPPORTED_LOCALES:
            self.lang_combo.addItem(locale, locale)
        self.lang_combo.setCurrentText(self.tr_.locale)
        self.lang_combo.currentIndexChanged.connect(self._on_locale_changed)
        lang_box.addWidget(self.lang_label)
        lang_box.addWidget(self.lang_combo)
        heading.addLayout(lang_box)

        self.privacy = QLabel()
        self.privacy.setObjectName("privacy")
        heading.addWidget(self.privacy)
        layout.addLayout(heading)

        self.security_banner = QLabel()
        self.security_banner.setObjectName("banner")
        layout.addWidget(self.security_banner)

        file_frame = QFrame()
        file_frame.setObjectName("panel")
        file_layout = QHBoxLayout(file_frame)
        self.file_label = QLabel()
        self.file_label.setObjectName("fileLabel")
        self.choose_button = QPushButton()
        self.choose_button.clicked.connect(self.choose_file)
        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(self.choose_button)
        layout.addWidget(file_frame)

        self.summary = QLabel()
        self.summary.setObjectName("muted")
        layout.addWidget(self.summary)

        self.table = QTableWidget(0, 5)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)

        footer = QHBoxLayout()
        self.persist_key = QCheckBox()
        footer.addWidget(self.persist_key)
        footer.addStretch()
        self.generate = QPushButton()
        self.generate.setObjectName("primary")
        self.generate.setEnabled(False)
        self.generate.clicked.connect(self.generate_output)
        footer.addWidget(self.generate)
        layout.addLayout(footer)

        self.key_hint = QLabel()
        self.key_hint.setObjectName("muted")
        layout.addWidget(self.key_hint)

        self.setCentralWidget(root)
        self.setStyleSheet(STYLESHEET)

    def _retranslate(self) -> None:
        t = self.tr_.t
        self.setWindowTitle(t("app.title"))
        self.title.setText(t("app.title"))
        self.subtitle.setText(t("app.subtitle"))
        self.privacy.setText(f"● {t('app.local_only')}")
        self.lang_label.setText(t("app.language"))
        self.security_banner.setText(t("security.banner"))
        self.file_label.setText(
            self.input_path.name
            if self.input_path
            else t("file.none")
        )
        self.choose_button.setText(t("file.choose"))
        if self.columns:
            self.summary.setText(t("file.summary_loaded", count=len(self.columns)))
        else:
            self.summary.setText(t("file.summary_idle"))
        self.table.setHorizontalHeaderLabels(
            [
                t("table.column"),
                t("table.classification"),
                t("table.nonempty"),
                t("table.reasons"),
                t("table.action"),
            ]
        )
        self.persist_key.setText(t("key.persist"))
        self.key_hint.setText(t("key.session_hint"))
        self.generate.setText(t("generate.button"))
        if self.columns:
            self._populate_table()

    def _on_locale_changed(self) -> None:
        locale = self.lang_combo.currentData()
        self.tr_.set_locale(str(locale))
        _save_locale_pref(self.tr_.locale)
        self._retranslate()

    def choose_file(self) -> None:
        t = self.tr_.t
        filename, _ = QFileDialog.getOpenFileName(
            self, t("file.dialog_title"), "", t("file.filter")
        )
        if not filename:
            return
        try:
            initial = inspect_dataset(filename)
            nonempty = [sheet for sheet in initial["sheets"] if sheet["row_count"] > 0]
            suitable = [sheet for sheet in nonempty if sheet["suitable"]]
            sheets = suitable or nonempty
            sheet_name = None
            if len(sheets) > 1:
                from PySide6.QtWidgets import QInputDialog

                names = [sheet["name"] for sheet in sheets]
                selected, accepted = QInputDialog.getItem(
                    self,
                    t("sheet.dialog_title"),
                    t("sheet.dialog_label"),
                    names,
                    0,
                    False,
                )
                if not accepted:
                    return
                sheet_name = selected
                initial = inspect_dataset(filename, sheet_name)
            self.input_path = Path(filename)
            self.sheet_name = sheet_name
            self.columns = initial["columns"]
            label = self.input_path.name
            if sheet_name:
                label = f"{label} · {sheet_name}"
            self.file_label.setText(label)
            self.summary.setText(t("file.summary_loaded", count=len(self.columns)))
            self._populate_table()
            self.generate.setEnabled(True)
        except SanitizerError as exc:
            QMessageBox.warning(self, t("error.read_title"), str(exc))

    def _populate_table(self) -> None:
        t = self.tr_.t
        classification_labels = {
            "sensitive": t("classification.sensitive"),
            "potentially_sensitive": t("classification.potentially_sensitive"),
            "analysis_required": t("classification.analysis_required"),
            "restricted": t("classification.restricted"),
        }
        actions = [
            (t("action.pseudonymize"), "pseudonymize"),
            (t("action.remove"), "remove"),
            (t("action.keep"), "keep"),
        ]
        self.table.setRowCount(len(self.columns))
        for row, finding in enumerate(self.columns):
            values = [
                finding["column"],
                classification_labels.get(
                    finding["classification"], finding["classification"]
                ),
                str(finding["nonempty_count"]),
                "; ".join(finding["reasons"]),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)
            combo = QComboBox()
            classification = finding["classification"]
            if classification == "analysis_required":
                combo.addItem(t("action.keep"), "keep")
                combo.setEnabled(False)
            elif classification == "restricted":
                combo.addItem(t("action.remove"), "remove")
                combo.setEnabled(False)
            elif classification == "sensitive":
                for label, action in actions:
                    combo.addItem(label, action)
                combo.setCurrentIndex(0)
            else:
                combo.addItem(t("action.choose"), None)
                for label, action in actions:
                    combo.addItem(label, action)
            self.table.setCellWidget(row, 4, combo)

    def generate_output(self) -> None:
        if not self.input_path:
            return
        t = self.tr_.t
        rules: dict[str, str] = {}
        remove_columns: list[str] = []
        for row, finding in enumerate(self.columns):
            combo = self.table.cellWidget(row, 4)
            assert isinstance(combo, QComboBox)
            action = combo.currentData()
            if action is None:
                QMessageBox.information(
                    self,
                    t("generate.need_decision_title"),
                    t("generate.need_decision", column=finding["column"]),
                )
                return
            rules[finding["column"]] = action
            if action == "remove":
                remove_columns.append(finding["column"])
        if remove_columns:
            answer = QMessageBox.question(
                self,
                t("generate.confirm_remove_title"),
                t(
                    "generate.confirm_remove_body",
                    columns="\n".join(remove_columns),
                ),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        suggested = self.input_path.with_name(
            f"{self.input_path.stem}_sanitized{self.input_path.suffix}"
        )
        output, _ = QFileDialog.getSaveFileName(
            self,
            t("generate.save_title"),
            str(suggested),
            "CSV (*.csv);;Excel (*.xlsx)",
        )
        if not output:
            return
        store = OSKeyStore() if self.persist_key.isChecked() else MemoryKeyStore()
        try:
            result = sanitize_dataset(
                self.input_path,
                output,
                sheet_name=self.sheet_name,
                rules=rules,
                allow_remove=bool(remove_columns),
                keystore=store,
                persist_key=self.persist_key.isChecked(),
            )
            QMessageBox.information(
                self,
                t("generate.success_title"),
                t(
                    "generate.success_body",
                    records=result.processed_records,
                    output=result.output_path.name,
                    sha256=result.sha256,
                    report=result.report_path.name,
                ),
            )
        except SanitizerError as exc:
            QMessageBox.critical(self, t("error.export_title"), str(exc))


STYLESHEET = """
QWidget { background: #f6f8f7; color: #17211e; font-size: 13px; }
QLabel#title { font-size: 24px; font-weight: 700; }
QLabel#muted { color: #66736e; }
QLabel#privacy { color: #087f6b; font-size: 11px; font-weight: 700; }
QLabel#banner { color: #0b5f52; background: #e7f5f1; padding: 8px 12px; border-radius: 4px; }
QLabel#fileLabel { font-weight: 600; }
QFrame#panel { background: white; border: 1px solid #dce3df; border-radius: 6px; }
QPushButton { min-height: 34px; padding: 0 14px; border: 1px solid #bdc8c3; border-radius: 4px; background: white; }
QPushButton:hover { border-color: #087f6b; }
QPushButton#primary { background: #087f6b; color: white; border-color: #087f6b; font-weight: 700; }
QPushButton#primary:disabled { background: #aab5b0; border-color: #aab5b0; }
QTableWidget { background: white; border: 1px solid #dce3df; gridline-color: #e7ece9; alternate-background-color: #f8faf9; }
QHeaderView::section { background: #edf2ef; padding: 8px; border: 0; border-bottom: 1px solid #dce3df; font-weight: 600; }
QComboBox { min-height: 30px; padding: 0 8px; border: 1px solid #cbd5d0; border-radius: 3px; background: white; }
"""


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName("Cloud Data Sanitizer")
    palette = application.palette()
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#087f6b"))
    application.setPalette(palette)
    translator = get_translator(_load_locale_pref())
    window = SanitizerWindow(translator)
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
