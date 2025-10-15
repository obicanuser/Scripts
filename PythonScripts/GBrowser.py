import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QMessageBox
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import Qt, QUrl, QPoint
from PyQt6.QtNetwork import QNetworkAccessManager

try:
    from PyQt6.QtNetworkAuth import QOAuth2AuthorizationCodeFlow
except ImportError:
    print("QtNetworkAuth module not found. Please ensure PyQt6 is properly installed.")
    sys.exit(1)

class Browser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setWindowTitle("Simple Qt Browser")
        self.setGeometry(100, 100, 1000, 700)
        
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        
        self.network_manager = QNetworkAccessManager(self)
        
        self.browser = QWebEngineView(self.central_widget)
        self.layout.addWidget(self.browser)
        
        self.setup_oauth()
        
        self.overlay = DragOverlay(self)
        self.overlay.setGeometry(0, 0, self.width(), 40)
        self.overlay.show()

    def setup_oauth(self):
        CLIENT_ID = "your-client-id-here.apps.googleusercontent.com"
        CLIENT_SECRET = "your-client-secret-here"
        AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
        TOKEN_URL = "https://oauth2.googleapis.com/token"
        REDIRECT_URI = "http://localhost:8000"
        
        self.oauth2 = QOAuth2AuthorizationCodeFlow(self)
        self.oauth2.setAuthorizationUrl(QUrl(AUTH_URL))
        self.oauth2.setAccessTokenUrl(QUrl(TOKEN_URL))
        self.oauth2.setClientIdentifier(CLIENT_ID)
        self.oauth2.setClientIdentifierSharedKey(CLIENT_SECRET)
        self.oauth2.setScope("openid email profile")
        self.oauth2.setNetworkAccessManager(self.network_manager)
        
        self.oauth2.granted.connect(self.on_auth_granted)
        self.oauth2.statusChanged.connect(self.on_status_changed)
        self.oauth2.setRedirectUri(REDIRECT_URI)
        
        self.browser.urlChanged.connect(self.handle_url_change)
        self.oauth2.grant()

    def on_auth_granted(self):
        access_token = self.oauth2.token()
        print("Authentication successful! Access token:", access_token)
        self.browser.setUrl(QUrl("https://www.googleapis.com/oauth2/v1/userinfo?alt=json"))

    def on_status_changed(self, status):
        print("Auth status changed:", status)
        if status == QOAuth2AuthorizationCodeFlow.Status.Failed:
            QMessageBox.warning(self, "Error", "Authentication failed")

    def handle_url_change(self, url):
        self.oauth2.setModifyParametersFunction(
            lambda stage, params: params
        )

    def resizeEvent(self, event):
        self.overlay.setGeometry(0, 0, self.width(), 40)
        super().resizeEvent(event)

class DragOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self._dragging = False
        self._drag_position = QPoint()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._drag_position = event.globalPosition().toPoint() - self.window().pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._dragging and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Browser()
    window.show()
    sys.exit(app.exec())