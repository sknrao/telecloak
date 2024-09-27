import spacy
nlp = spacy.load("GPTNEW_log_ner_model")
import re

listOfStopWords = [
    "ID",
    "name",
    "login",
    "authenticated",
    "logged in",
    "session",
    "access",
    "permissions",
    "role",
    "action",
    "created",
    "updated",
    "deleted",
    "IP",
    "attempt",
    "profile",
    "activity",
    "failed",
    "agent",
    "password",
    "settings",
    "logout",
    "location",
    "email",
    "registration",
    "group",
    "status",
    "request",
    "input",
    "output",
    "timestamp",
    "token",
    "connection",
    "interaction",
    "device",
    "history",
    "behavior",
    "browser",
    "preferences",
    "type",
    "identifier",
    "authenticated token",
    "reset",
    "data",
    "rights",
    "error",
    "message",
    "notification",
    "timestamp"
]

def presidio(text: str):
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import RecognizerResult, OperatorConfig
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    analyzer = AnalyzerEngine()       # Analyzer
    anonymizer = AnonymizerEngine()   # Anonymizer
    results = analyzer.analyze(text=text, entities=["PERSON", "LOCATION", "URL", "NRP", "EMAIL_ADDRESS", "IP_ADDRESS"], language='en')  #  "DATE_TIME","IP_ADDRESS"
    result_list = [
        (text[result.start:result.end], result.entity_type)
        for result in results
    ]
    text = anonymizer.anonymize(text=text, analyzer_results=results)

    return text.text.replace('<', '').replace('>', ''), result_list

def presidioDate(text: str):
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import RecognizerResult, OperatorConfig
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    analyzer = AnalyzerEngine()       # Analyzer
    anonymizer = AnonymizerEngine()   # Anonymizer
    results = analyzer.analyze(text=text, entities=["DATE_TIME"], language='en')  #  ,"IP_ADDRESS"
    result_list = [
        (text[result.start:result.end], result.entity_type)
        for result in results
    ]
    text = anonymizer.anonymize(text=text, analyzer_results=results)

    return text.text.replace('<', '').replace('>', ''), result_list

def pre_process(text):
    split_text = re.split(r'[\[\]{:}/=",\' ]', text)
    preprocessed_text = " ".join(filter(None, split_text))
    return preprocessed_text

def replace_entities_with_types(original_text, entity_list):
    # entity_map = {}
    for entity, ent_type in entity_list:
        original_text = original_text.replace(entity,ent_type)
    
    return original_text

def anonymize_seq(ex):
    preprocessed_text = pre_process(ex)    
    presidio_output, results = presidio(preprocessed_text)

    anonymized_text1 = replace_entities_with_types(ex, results)
    doc = nlp(pre_process(presidio_output))
    entity_list=[]
    for ent in doc.ents:
        if ent.text not in listOfStopWords:
            if ent.label_ == "PER":
                ent.label_ = "PERSON"
            elif ent.label_ == "LOC":
                ent.label_ = "LOCATION"
            elif ent.label_ == "ADDRESS":
                ent.label_ = "LOCATION"
            if(ent.label_ != ent.text):
                entity_list.append((ent.text, ent.label_))
    anonymized_text2 = replace_entities_with_types(anonymized_text1, entity_list)
    anonymized_text2 = presidioDate(anonymized_text2)[0]
    return anonymized_text2
