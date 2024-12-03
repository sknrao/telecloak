import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.layers import Input, Dense, Activation
from tensorflow.keras import Model
from tensorflow.keras.models import load_model

def build_autoencoder(dim_input, dim_layer_1, dim_layer_2):
    input_layer = Input(shape=(dim_input,))
    x = Activation("relu")(input_layer)
    x = Dense(dim_layer_1)(x)
    x = Activation("relu")(x)
    bottleneck_layer = Dense(dim_layer_2)(x)
    x = Activation("relu")(bottleneck_layer)
    x = Dense(dim_layer_1)(x)
    x = Activation("relu")(x)
    output_layer = Dense(dim_input, activation='linear')(x)

    encoder = Model(inputs=input_layer, outputs=bottleneck_layer)   
    autoencoder = Model(inputs=input_layer, outputs=output_layer)
    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder, encoder

def anonymize_ae(df_path, model_path='./best_model.keras', weights_path='./best_model.weights.h5'):
    df = pd.read_csv(df_path)
    df.columns = df.columns.str.strip()

    numerical_cols = df.select_dtypes(include=['float64', 'int64']).columns
    scaler = MinMaxScaler()
    df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

    data_scaled = df[numerical_cols].values

    dim_layer_input = data_scaled.shape[1]
    dim_layer_1 = max(int(3 * dim_layer_input / 4), 1)
    dim_layer_2 = max(int(dim_layer_input / 2), 1)

    autoencoder, encoder = build_autoencoder(
        dim_input=dim_layer_input,
        dim_layer_1=dim_layer_1,
        dim_layer_2=dim_layer_2,   
    )

    autoencoder = load_model(model_path)    
    autoencoder.load_weights(weights_path)

    data_encoded = encoder.predict(data_scaled)
    df_encoded = pd.DataFrame(data_encoded, columns=[f"encoded_{i+1}" for i in range(data_encoded.shape[1])])

    return df_encoded

if __name__ == "__main__":
    anonymized_data = anonymize_ae('/home/mathelet/telecloak/anonymizers/aenon/CWRU_bearing.csv', model_path='./best_model.keras', weights_path='./best_model.weights.h5')
    anonymized_data.to_csv('anonymized_data.csv', index=False)
        