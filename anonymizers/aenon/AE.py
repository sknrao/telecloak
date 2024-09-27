
#get_ipython().system('pip install -U scikit-learn scipy matplotlib')
#get_ipython().syst
# em('pip install tensorflow')
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_validate
from sklearn.inspection import permutation_importance
from numpy import mean, max, prod, array, hstack
from numpy.random import choice
#import matplotlib.pyplot as plt
from tensorflow.keras.layers import Input, Dense, Dropout, Activation, BatchNormalization, LeakyReLU
from tensorflow.keras import Model
from tensorflow.keras.models import load_model
from tensorflow.keras.datasets import mnist
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.utils import plot_model
#from tqdm import tqdm
import os



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
    
    encoder = Model(input_layer, bottleneck_layer)
    autoencoder = Model(input_layer, output_layer)
    autoencoder.compile(optimizer='adam', loss='mse')
    
    return autoencoder, encoder

def anonymize_ae(df_path):
    df = pd.read_csv(df_path, sep=",")
    df.columns = df.columns.str.replace('"', '').str.strip()
    print(df.columns)
    print(df.head())
    feature_columns = df.iloc[:, :9].columns
    #feature_columns = ['max','min','mean','sd','rms','skewness','kurtosis','crest','form']
    target_column = df.iloc[:,9].name
    X = df[feature_columns]
    y = df[target_column]
    min_max_scaler = MinMaxScaler()
    X = min_max_scaler.fit_transform(X)

    #building autoencoder
    dim_layer_input = X.shape[1]
    dim_layer_1 = max((int(3*dim_layer_input/4), 1))
    dim_layer_2 = max((int(dim_layer_input/2), 1))
    autoencoder, encoder = build_autoencoder(
        dim_input=dim_layer_input,
        dim_layer_1=dim_layer_1,
        dim_layer_2=dim_layer_2,   
    )


    autoencoder = load_model('./best_model.h5')
    #print(autoencoder.summary())
    encoder_layer_output = autoencoder.layers[4].output  
    encoder = Model(inputs=autoencoder.input, outputs=encoder_layer_output)

    X_encoded = encoder.predict(X)
    df_encoded = pd.DataFrame(X_encoded, columns=[f"encoded_{i+1}" for i in range(X_encoded.shape[1])])
    #print(f"Encoded Train Shape: {X_train_encoded.shape}")

    print("Anonymized Training Data:")
    print(df_encoded.head())
    return df_encoded
