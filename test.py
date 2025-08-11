import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import warnings
warnings.filterwarnings('ignore')

class WeatherLSTMPredictor:
    def __init__(self, sequence_length=30, prediction_days=7):
        """
        Modèle LSTM pour prédiction météorologique multi-variables
        
        Args:
            sequence_length (int): Nombre de jours historiques à utiliser (30)
            prediction_days (int): Nombre de jours à prédire (7)
        """
        self.sequence_length = sequence_length
        self.prediction_days = prediction_days
        self.scalers = {}
        self.model = None
        self.feature_names = ['temperature', 'pression', 'humidite', 'precipitations']
        
    def generate_sample_data(self, n_days=1000):
        """Génère des données météorologiques simulées pour la démonstration"""
        np.random.seed(42)
        dates = pd.date_range('2021-01-01', periods=n_days, freq='D')
        
        # Simulation de données météorologiques réalistes
        t = np.arange(n_days)
        
        # Température avec tendance saisonnière
        temperature = 15 + 10 * np.sin(2 * np.pi * t / 365.25) + np.random.normal(0, 3, n_days)
        
        # Pression atmosphérique (1000-1030 hPa)
        pression = 1015 + 10 * np.sin(2 * np.pi * t / 30) + np.random.normal(0, 5, n_days)
        
        # Humidité (20-90%)
        humidite = 60 + 20 * np.sin(2 * np.pi * t / 365.25 + np.pi/4) + np.random.normal(0, 10, n_days)
        humidite = np.clip(humidite, 20, 90)
        
        # Précipitations (0-20mm, avec corrélation à l'humidité)
        precipitations = np.maximum(0, (humidite - 50) / 10 + np.random.exponential(1, n_days))
        precipitations = np.clip(precipitations, 0, 20)
        
        data = pd.DataFrame({
            'date': dates,
            'temperature': temperature,
            'pression': pression,
            'humidite': humidite,
            'precipitations': precipitations
        })
        
        return data
    
    def prepare_data(self, data):
        """Prépare les données pour l'entraînement du modèle LSTM"""
        # Normalisation des données
        scaled_data = data.copy()
        
        for feature in self.feature_names:
            scaler = MinMaxScaler()
            scaled_data[feature] = scaler.fit_transform(data[feature].values.reshape(-1, 1)).flatten()
            self.scalers[feature] = scaler
        
        # Création des séquences
        X, y = [], []
        
        for i in range(self.sequence_length, len(scaled_data) - self.prediction_days + 1):
            # Séquence d'entrée (30 jours)
            X.append(scaled_data[self.feature_names].iloc[i-self.sequence_length:i].values)
            # Séquence de sortie (7 jours)
            y.append(scaled_data[self.feature_names].iloc[i:i+self.prediction_days].values)
        
        return np.array(X), np.array(y)
    
    def build_model(self):
        """Construit le modèle LSTM"""
        model = Sequential([
            LSTM(100, return_sequences=True, input_shape=(self.sequence_length, len(self.feature_names))),
            Dropout(0.2),
            LSTM(100, return_sequences=True),
            Dropout(0.2),
            LSTM(50, return_sequences=False),
            Dropout(0.2),
            Dense(50, activation='relu'),
            Dense(self.prediction_days * len(self.feature_names))
        ])
        
        # Reshape pour obtenir la forme correcte de sortie
        model.add(tf.keras.layers.Reshape((self.prediction_days, len(self.feature_names))))
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def train(self, data, validation_split=0.2, epochs=100, batch_size=32):
        """Entraîne le modèle LSTM"""
        print("Préparation des données...")
        X, y = self.prepare_data(data)
        
        print(f"Forme des données d'entrée: {X.shape}")
        print(f"Forme des données de sortie: {y.shape}")
        
        # Division train/validation
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        print("Construction du modèle...")
        self.model = self.build_model()
        print(self.model.summary())
        
        # Callbacks
        early_stopping = EarlyStopping(
            monitor='val_loss',
            patience=15,
            restore_best_weights=True
        )
        
        print("Entraînement du modèle...")
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping],
            verbose=1
        )
        
        return history
    
    def predict(self, last_sequence):
        """Fait une prédiction pour les 7 prochains jours"""
        if self.model is None:
            raise ValueError("Le modèle doit être entraîné avant de faire des prédictions")
        
        # Normaliser la séquence d'entrée
        scaled_sequence = np.zeros_like(last_sequence)
        for i, feature in enumerate(self.feature_names):
            scaled_sequence[:, i] = self.scalers[feature].transform(
                last_sequence[:, i].reshape(-1, 1)
            ).flatten()
        
        # Prédiction
        scaled_prediction = self.model.predict(scaled_sequence.reshape(1, self.sequence_length, -1))
        
        # Dénormalisation
        prediction = np.zeros_like(scaled_prediction[0])
        for i, feature in enumerate(self.feature_names):
            prediction[:, i] = self.scalers[feature].inverse_transform(
                scaled_prediction[0, :, i].reshape(-1, 1)
            ).flatten()
        
        return prediction
    
    def evaluate_model(self, data, plot_results=True):
        """Évalue le modèle sur les données de test"""
        X, y = self.prepare_data(data)
        
        # Utiliser les dernières données pour le test
        test_size = min(100, len(X) // 5)
        X_test = X[-test_size:]
        y_test = y[-test_size:]
        
        # Prédictions
        predictions = self.model.predict(X_test)
        
        # Dénormalisation pour calculer les métriques
        y_test_denorm = np.zeros_like(y_test)
        pred_denorm = np.zeros_like(predictions)
        
        for i, feature in enumerate(self.feature_names):
            for j in range(self.prediction_days):
                y_test_denorm[:, j, i] = self.scalers[feature].inverse_transform(
                    y_test[:, j, i].reshape(-1, 1)
                ).flatten()
                pred_denorm[:, j, i] = self.scalers[feature].inverse_transform(
                    predictions[:, j, i].reshape(-1, 1)
                ).flatten()
        
        # Calcul des métriques
        metrics = {}
        for i, feature in enumerate(self.feature_names):
            mse = mean_squared_error(y_test_denorm[:, :, i], pred_denorm[:, :, i])
            mae = mean_absolute_error(y_test_denorm[:, :, i], pred_denorm[:, :, i])
            metrics[feature] = {'MSE': mse, 'MAE': mae, 'RMSE': np.sqrt(mse)}
        
        # Affichage des résultats
        print("\n=== ÉVALUATION DU MODÈLE ===")
        for feature, metric in metrics.items():
            print(f"\n{feature.upper()}:")
            print(f"  RMSE: {metric['RMSE']:.4f}")
            print(f"  MAE:  {metric['MAE']:.4f}")
        
        if plot_results:
            self.plot_predictions(y_test_denorm, pred_denorm)
        
        return metrics
    
    def plot_predictions(self, y_true, y_pred, n_samples=3):
        """Visualise les prédictions vs valeurs réelles"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        axes = axes.flatten()
        
        for i, feature in enumerate(self.feature_names):
            ax = axes[i]
            
            for j in range(min(n_samples, len(y_true))):
                days = range(1, self.prediction_days + 1)
                ax.plot(days, y_true[j, :, i], 'o-', alpha=0.7, label=f'Réel {j+1}' if i == 0 else "")
                ax.plot(days, y_pred[j, :, i], 's--', alpha=0.7, label=f'Prédit {j+1}' if i == 0 else "")
            
            ax.set_title(f'Prédictions - {feature.capitalize()}')
            ax.set_xlabel('Jour de prédiction')
            ax.set_ylabel(feature.capitalize())
            ax.grid(True, alpha=0.3)
            if i == 0:
                ax.legend()
        
        plt.tight_layout()
        plt.show()
    
    def predict_next_week(self, recent_data):
        """Prédit les 7 prochains jours à partir des données récentes"""
        if len(recent_data) < self.sequence_length:
            raise ValueError(f"Il faut au moins {self.sequence_length} jours de données récentes")
        
        # Prendre les 30 derniers jours
        last_sequence = recent_data[self.feature_names].iloc[-self.sequence_length:].values
        
        # Faire la prédiction
        prediction = self.predict(last_sequence)
        
        # Créer un DataFrame avec les résultats
        future_dates = pd.date_range(
            start=recent_data['date'].iloc[-1] + pd.Timedelta(days=1),
            periods=self.prediction_days,
            freq='D'
        )
        
        prediction_df = pd.DataFrame(prediction, columns=self.feature_names)
        prediction_df['date'] = future_dates
        
        return prediction_df

# Exemple d'utilisation
if __name__ == "__main__":
    print("=== MODÈLE LSTM POUR PRÉDICTION MÉTÉOROLOGIQUE ===\n")
    
    # Initialisation du modèle
    predictor = WeatherLSTMPredictor(sequence_length=30, prediction_days=7)
    
    # Génération de données d'exemple
    print("1. Génération des données d'exemple...")
    data = predictor.generate_sample_data(n_days=1000)
    print(f"Données générées: {len(data)} jours")
    print("\nAperçu des données:")
    print(data.head())
    
    # Entraînement du modèle
    print("\n2. Entraînement du modèle LSTM...")
    history = predictor.train(data, epochs=50, batch_size=32)
    
    # Évaluation
    print("\n3. Évaluation du modèle...")
    metrics = predictor.evaluate_model(data, plot_results=True)
    
    # Prédiction pour la semaine prochaine
    print("\n4. Prédiction pour les 7 prochains jours...")
    prediction = predictor.predict_next_week(data)
    print("\nPrédictions:")
    print(prediction)
    
    # Visualisation des dernières données et prédictions
    plt.figure(figsize=(15, 10))
    
    recent_data = data.tail(14)  # 2 dernières semaines
    
    for i, feature in enumerate(predictor.feature_names):
        plt.subplot(2, 2, i+1)
        
        # Données historiques
        plt.plot(range(-13, 1), recent_data[feature].values, 'o-', 
                label='Données historiques', color='blue')
        
        # Prédictions
        plt.plot(range(1, 8), prediction[feature].values, 's--', 
                label='Prédictions', color='red')
        
        plt.axvline(x=0, color='gray', linestyle=':', alpha=0.7, label='Aujourd\'hui')
        plt.title(f'Prédictions - {feature.capitalize()}')
        plt.xlabel('Jours (0 = aujourd\'hui)')
        plt.ylabel(feature.capitalize())
        plt.legend()
        plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()
    
    print("\n=== MODÈLE PRÊT À L'EMPLOI ===")
    print("Le modèle peut maintenant prédire les conditions météorologiques")
    print("pour les 7 prochains jours à partir des 30 derniers jours de données.")