from .classification import train_demo_model
if __name__ == '__main__':
    p = train_demo_model()
    print('Model saved to', p)
