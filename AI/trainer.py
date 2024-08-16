import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import Trainer, TrainingArguments
from datasets import load_dataset, Dataset


def train_sqlinjection(training_data_file: str):
    """
    Trains a machine learning model to detect SQL injections.
    This function takes a file path to a text file containing SQL
    injection examples,one per line, and trains a machine
    learning model to classify them.

    Args:
        training_data_file (str): The path to the text file
        containing SQL injection examples.

    Returns:
        None
    """
    with open(training_data_file, 'r') as file:
        sql_injections = file.readlines()

    data = {
        'text': sql_injections,
        'label': [1] * len(sql_injections)
    }

    dataset = Dataset.from_dict(data)

    tokenizer = AutoTokenizer.from_pretrained('falcon180b')
    model = AutoModelForSequenceClassification.from_pretrained('falcon180b',
                                                               num_labels=2)

    def tokenize_function(example):
        """
        Tokenizes a given example using the provided tokenizer.

        Args:
            example (dict): A dictionary containing the text to be tokenized.

        Returns:
            dict: A dictionary containing the tokenized text.
        """
        return tokenizer(example['text'], padding='max_length',
                         truncation=True)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    training_args = TrainingArguments(
        output_dir='./results',
        per_device_train_batch_size=8,
        num_train_epochs=3,
        logging_dir='./logs',
        logging_steps=10,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset
    )

    trainer.train()

    model.save_pretrained('./trained_model')


def train_xss_detection(training_data_file: str):
    """
    Trains an XSS detection model using the provided training data file.

    Args:
        training_data_file (str): The path to the file containing XSS patterns.

    Returns:
        None
    """
    with open(training_data_file, 'r') as file:
        xss_patterns = file.readlines()

    data = {
        'text': xss_patterns,
        'label': [1] * len(xss_patterns)
    }

    dataset = Dataset.from_dict(data)

    train_model(dataset, 'xss_model')


def train_model(dataset, model_name):
    """
    Trains a machine learning model using the
    provided dataset and saves the trained model.

    Args:
        dataset: The dataset to use for training the model.
        model_name: The name of the model to be trained.

    Returns:
        None
    """
    tokenizer = AutoTokenizer.from_pretrained('falcon180b')
    model = AutoModelForSequenceClassification.from_pretrained('falcon180b',
                                                               num_labels=2)

    def tokenize_function(example):
        return tokenizer(example['text'], padding='max_length',
                         truncation=True)

    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    training_args = TrainingArguments(
        output_dir=f'./results/{model_name}',
        per_device_train_batch_size=8,
        num_train_epochs=3,
        logging_dir=f'./logs/{model_name}',
        logging_steps=10,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset
    )

    trainer.train()
    model.save_pretrained(f'./trained_model/{model_name}')


def train_csrf_detection(training_data_file: str):
    """
    Trains a CSRF detection model using the provided training data file.

    Args:
        training_data_file (str): The path to the file
        containing the training data.

    Returns:
        None
    """
    with open(training_data_file, 'r') as file:
        csrf_patterns = file.readlines()

    data = {
        'text': csrf_patterns,
        'label': [1] * len(csrf_patterns)
    }

    dataset = Dataset.from_dict(data)
    train_model(dataset, 'csrf_model')


def train_session_hijacking_detection(training_data_file: str):
    """
    Trains a session hijacking detection model using
    the provided training data file.

    Args:
        training_data_file (str): The path to the file
        containing the training data.

    Returns:
        None
    """
    with open(training_data_file, 'r') as file:
        hijacking_patterns = file.readlines()

    data = {
        'text': hijacking_patterns,
        'label': [1] * len(hijacking_patterns)
    }

    dataset = Dataset.from_dict(data)
    train_model(dataset, 'session_hijacking_model')


def train_custom_threat_detection(training_data_file: str, model_name: str):
    """
    Trains a custom threat detection model using the
    provided training data file and model name.

    Args:
        training_data_file (str): The path to the file
        containing the training data.
        model_name (str): The name of the model to be trained.

    Returns:
        None
    """
    with open(training_data_file, 'r') as file:
        threat_patterns = file.readlines()

    data = {
        'text': threat_patterns,
        'label': [1] * len(threat_patterns)
    }

    dataset = Dataset.from_dict(data)
    train_model(dataset, model_name)
