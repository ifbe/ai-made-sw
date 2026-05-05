import SwiftUI
import MetalKit

struct ContentView: View {
    @StateObject private var sensorManager = SensorManager.shared
    @StateObject private var socketManager = SocketManager.shared

    var body: some View {
        ZStack {
            // Metal 3D view
            MetalView(sensorManager: sensorManager)
                .ignoresSafeArea()

            // UI overlay - 4 corners
            UISpace(sensorManager: sensorManager, socketManager: socketManager)
        }
        .onAppear {
            sensorManager.start()
        }
        .onDisappear {
            sensorManager.stop()
        }
    }
}