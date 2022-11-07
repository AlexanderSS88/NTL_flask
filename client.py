import requests


"""POST USER"""
data = requests.post(
    'http://127.0.0.1:5000/flask/user',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''})
print(data.status_code)
print(data.text)


"""GET USER"""
data = requests.get(
    'http://127.0.0.1:5000/flask/user/32',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''})
print(data.status_code)
print(data.text)


"""POST ADV"""
data = requests.post(
    'http://127.0.0.1:5000/flask/user/adv',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''
        },
    params={'title': 'auy5uu',
            'description': 'hh2353h'})
print(data.status_code)
print(data.text)


"""PATCH ADV"""
data = requests.patch(
    'http://127.0.0.1:5000/flask/user/adv/11',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''
        },
    params={'title': '77att57u4',
            'description': 'hhhgrr111'})
print(data.status_code)
print(data.text)


"""GET ADV"""
data = requests.get(
    'http://127.0.0.1:5000/flask/user/adv/11',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''
        })
print(data.status_code)
print(data.text)


"""DELETE ADV"""
data = requests.delete(
    'http://127.0.0.1:5000/flask/user/adv/9',
    json={
        'name': 'Super_Nur',
        'psw': 'AAAdbsbs46.!qdgwo;t$',
        'mail': ''
        })
print(data.status_code)
print(data.text)


