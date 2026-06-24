- Since we'll need math, here is a [section](https://academy.hackthebox.com/app/module/290/section/3288) where you can refer to if you see a symbol you don't understand.

- So to start : ==Deep learning== (DL) is a subfield of ==Machine Learning== (ML) , which itself is a subfield of ==AI==

# Supervised Learning Algorithms 
- It's the cornerstone of many ==ML== apps, enables systems to learn from labeled data and make accurate predictions:
	- It's like having a set of examples with the correct answers already provided.
- It aims to learn a ==mapping function== to predict the label for new data, it does that by identifying patterns and relationships between inputs and outputs 

## Core Concepts in Supervised Learning
### Training Data
The labeled dataset used to train the `ML` model.
### Features
The measurable properties or characteristics of the data that serve as input to the model.
### Labels
The known outcomes
### Model
Mathematical representation of the relationship between the features and the labels.
### Training
The process of feeding the `training data` to the algorithm and adjusting the model's parameters to minimize prediction errors.
### Prediction

### Inference

### Evaluation
Involves assessing the model's performance to determine its accuracy and generalization ability to new data. Common evaluation metrics include:
- `Accuracy:` The proportion of correct predictions made by the model.
- `Precision:` The proportion of true positive predictions among all positive predictions.
- `Recall:` The proportion of true positive predictions among all actual positive instances.
- `F1-score:` A harmonic mean of precision and recall, providing a balanced measure of the model's performance.
### Generalization
The model's ability to accurately predict outcomes for new, unseen data not used during training.
### Overfitting
Occurs when a model learns the training data too well, including noise and outliers. This can lead to poor generalization of new data, as the model has memorized the training set instead of learning the underlying patterns.
### Underfitting
Occurs when a model is too simple to capture the underlying patterns in the data. This results in poor performance on both the training data and new, unseen data.
### Cross-Validation
Technique used to assess how well a model will generalize to an independent dataset. It involves splitting the data into multiple subsets (folds) and training the model on different combinations of these folds while validating it on the remaining fold. This helps reduce overfitting
### Regularization
Technique used to prevent overfitting by adding a penalty term to the loss function. This penalty discourages the model from learning overly complex patterns that might not generalize well. Common regularization techniques include:
- `L1 Regularization:` Adds a penalty equal to the absolute value of the magnitude of coefficients.
- `L2 Regularization:` Adds a penalty equal to the square of the magnitude of coefficients.

## Linear Regression
