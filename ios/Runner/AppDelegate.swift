import UIKit
import Flutter
import WatchConnectivity

@available(iOS 9.3, *)

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate, WCSessionDelegate {
    let defaults = UserDefaults.standard
    
    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
    }
    
    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        if (userInfo["token_set"] != nil) {
            defaults.set(true, forKey: "token_set")
        }
    }
    
    func session(_ session: WCSession, didReceiveMessage message: [String : Any]) {
        let controller : FlutterViewController = window?.rootViewController as! FlutterViewController
        let channel = FlutterMethodChannel(name: "fduhole",
                                           binaryMessenger: controller.binaryMessenger)
        channel.invokeMethod("get_token", arguments: nil)
    }
    
    func sessionDidBecomeInactive(_ session: WCSession) {
    }
    
    func sessionDidDeactivate(_ session: WCSession) {
    }
    
    func sendString(text: String) {
        let session = WCSession.default;
        if(WCSession.isSupported()){
            DispatchQueue.main.async {
                session.sendMessage(["token": text], replyHandler: nil)
            }
        }
    }
    
    override func application(_ application: UIApplication,
                              didRegisterForRemoteNotificationsWithDeviceToken
                              deviceToken: Data) {
        let token: String = deviceToken.map { String(format: "%.2hhx", $0) }.joined()
        let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? "null_device_id"
        /* Send token to FDUHole */
        let controller : FlutterViewController = window?.rootViewController as! FlutterViewController
        let channel = FlutterMethodChannel(name: "fduhole", binaryMessenger: controller.binaryMessenger)
        channel.invokeMethod("upload_apns_token", arguments: ["token": token, "id": deviceId])
    }
    
    
    override func application(_ application: UIApplication,
                              didFailToRegisterForRemoteNotificationsWithError
                              error: Error) {
        if #available(iOS 10.0, *) {
            UNUserNotificationCenter.current().getNotificationSettings { settings in
                guard (settings.authorizationStatus == .authorized) ||
                        (settings.authorizationStatus == .notDetermined) else { return }
                DispatchQueue.main.asyncAfter(deadline: .now() + 120.0) {
                    application.registerForRemoteNotifications()
                }
            }
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 120.0) {
                application.registerForRemoteNotifications()
            }
        }
    }
    
    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        
        /* Flutter */
        let controller : FlutterViewController = window?.rootViewController as! FlutterViewController
        let channel = FlutterMethodChannel(name: "fduhole", binaryMessenger: controller.binaryMessenger)
        channel.setMethodCallHandler({
            (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            switch (call.method) {
            case "request_notification_permission":
                if #available(iOS 10.0, *) {
                    let authOptions: UNAuthorizationOptions = [.alert, .badge, .sound]
                    UNUserNotificationCenter.current().requestAuthorization(
                        options: authOptions,
                        completionHandler: {_, _ in })
                    UNUserNotificationCenter.current().delegate = self
                } else {
                    let settings: UIUserNotificationSettings =
                    UIUserNotificationSettings(types: [.alert, .badge, .sound], categories: nil)
                    application.registerUserNotificationSettings(settings)
                }
            case "send_token":
                self.sendString(text: call.arguments as! String)
            default:
                break
            }
        })
        
        /* APNS support */
        application.registerForRemoteNotifications()
        
        /* watchOS Support */
        if(WCSession.isSupported()){
            let session = WCSession.default;
            session.delegate = self;
            session.activate();
        }
        
        GeneratedPluginRegistrant.register(with: self)
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }
    //quick_actions item click not work, should copy this method to AppDelegate.swift'
    // @see Issue (https://github.com/flutter/flutter/issues/46155)
    override func application(_ application: UIApplication, performActionFor shortcutItem: UIApplicationShortcutItem, completionHandler: @escaping (Bool) -> Void) {
        let controller = window.rootViewController as? FlutterViewController
        
        let channel = FlutterMethodChannel(name: "plugins.flutter.io/quick_actions", binaryMessenger: controller! as! FlutterBinaryMessenger)
        channel.invokeMethod("launch", arguments: shortcutItem.type)
    }
}
