from virtualpy_detector import virtualpydetector

if __name__ == "__main__":
    VPD = virtualpydetector()
    if VPD.detect():
        print("virtualpy-detector: Detected")
    else:
        print("virtualpy-detector: Not Detected")
