<div align="center">
<h1><a id="intro">Лабораторная работа №8</a><br></h1>
<a href="https://docs.github.com/en"><img src="https://img.shields.io/static/v1?logo=github&logoColor=fff&label=&message=Docs&color=36393f&style=flat" alt="GitHub Docs"></a>
<a href="https://daringfireball.net/projects/markdown"><img src="https://img.shields.io/static/v1?logo=markdown&logoColor=fff&label=&message=Markdown&color=36393f&style=flat" alt="Markdown"></a> 
<a href="https://symbl.cc/en/unicode-table"><img src="https://img.shields.io/static/v1?logo=unicode&logoColor=fff&label=&message=Unicode&color=36393f&style=flat" alt="Unicode"></a> 
<a href="https://shields.io"><img src="https://img.shields.io/static/v1?logo=shieldsdotio&logoColor=fff&label=&message=Shields&color=36393f&style=flat" alt="Shields"></a>
<a href="https://img.shields.io/badge/Risk_Analyze-2448a2"><img src="https://img.shields.io/badge/Course-Risk_Analysis-2448a2" alt= "RA"></a> <img src="https://img.shields.io/badge/AppSec-2448a2" alt= "RA"></a> <img src="https://img.shields.io/badge/Contributor-Можжухин_А._Н.-8b9aff" alt="Contributor Badge"></a></div>

***



***

## Задание

- [x] 1. Разверните и подготовьте окружение для уязвимого приложения

```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt && vulnerable-app/requirements.txt
```

- [x] 2. Запустите уязвимое приложение

```bash
$ docker-compose up -d --build  # http://localhost:8080
```

- [x] 3. Проверьте доступность приложения

```bash
$ curl -i http://localhost:8080
```

Вывод такой:

```bash
HTTP/1.1 200 OK
Server: xxxxx/xxxxx Python/xxxxx
Date: xxxxx, xxxxx xxxxx 2025 xxxxx GMT
Content-Type: text/html; charset=utf-8
Content-Length: 625
Set-Cookie: session=guest-session-id; Path=/
Connection: close


    <h1>Vulnerable DAST Demo App</h1>
    <p>Пример уязвимого приложения для лабораторной по DAST.</p>
    <ul>
      <li><a href="/echo?msg=Hello">Reflected XSS / echo</a></li>
      <li><a href="/search?username=admin">SQL Injection / search</a></li>
      <li><a href="/login">Небезопасный логин</a></li>
      <li><a href="/profile">Профиль (зависит от cookie)</a></li>
      <li><a href="/admin">«Админка» без нормальной авторизации</a></li>
      <li><a href="/files/">Directory listing</a></li>
    </ul>
```

- [x] 4. Проведите ручное исследование уязвимостей и опишите почему такое происходит, каким образом реализуются уязвимости и дайте им определение
- [x] 4.1. `/echo` - проверить отражение параметра  `msg`  в `HTML` и использовать `payload` вида  `<script>alert('XSS')</script>` зафиксировав его поведение

```bash
http://localhost:8080/echo?msg=<script>alert('hack with XSS')</script>
```

- [x] 4.2. `/search` - проверить обычный запрос  `?username=admin` и использовать строку  `?username=admin' OR '1'='1` зафиксировав его поведение описав признак SQLi

```bash
http://localhost:8080/search?username=admin' OR '1'='1
```

- [x] 4.3. `/login` - войти под  `admin`  и  `user` проверив логику на открытые пароли и простые SQL‑запросы
- [x] 4.4. `/profile` - изменить `cookie  role`  на  `admin`  через `DevTools` → `Application` → `Cookies` и обновить  `/profile` (возможно создать `cookie`
- [x] 4.5. `/admin` -  проверить, что доступ запрещён без `cookie  role=admin` и далее подделать `cookie`, что «админка» открывается путем изменения через `DevTools`. **Подсказка:** доступ завязан на значение cookie, без подписи/ токена/ серверной проверки.
- [x] 4.6. `/files/` - просмотрите `directory listing` и откройте один из файлов убедившись, что оно выводится

```bash
http://localhost:8080/files/secret.txt
```

- [x] 5. Доработайте по пп 4 лабораторную работу развив их содержимое, которое может выводиться (мин 1 пример)
- [x] 6. Поставьте `OWASP ZAP` и стяните образ конкртеной версии для него

```bash
$ brew install --cask zap
$ docker pull ghcr.io/zaproxy/zaproxy:stable
```

- [x] 7. Задайте переменные окружения для работы скриптов

```bash
$ export ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:stable
$ TARGET_URL="${TARGET_URL:-http://host.docker.internal:8080}"
```

- [x] 8. Запустите скрипт автоматического сканирования DAST `OWASP ZAP`

```bash
$ ./zap_scan.sh
```

- [x] 9. Изучите сгенерированные отчеты в `dast/reports` и опишите риски ИБ для них, без сценариев, так как ранее вы видели часть из их реализации
- [x] 10. Внесите исправления по данному отчету `DAST` для `vulnerable-app/app.py`
- [x] 11. Делайте все необходимые коммиты по шагам и отправляйте изменения в удалённый репозиторий
- [x] 12. Подготовьте отчет `gist`.


## Links

- [Docker](https://docs.docker.com/)
- [Flask Documentation](https://flask.palletsprojects.com/)  
- [odfpy – OpenDocument API for Python](https://github.com/eea/odfpy) 
- [openpyxl – Excel files in Python](https://openpyxl.readthedocs.io/)  
- [Markdown](https://stackedit.io)
- [Gist](https://gist.github.com)
- [GitHub CLI](https://cli.github.com)
- [OWASP ZAP](https://www.zaproxy.org/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)  
- [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)  
- [ZAP Docker images](https://www.zaproxy.org/docs/docker/)  
- [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)  
- [ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/)

Copyright (c) 2025 Alexey Mozhzhukhin