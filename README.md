Кэширующий DNS-сервер - это сервер, который хранит копии ответов на DNS-запросы в памяти, чтобы можно было быстро отвечать на повторные запросы к одним и тем же DNS-записям. 
Это повышает производительность и снижает задержку, поскольку серверу не нужно каждый раз запрашивать записи у вышестоящих DNS-серверов. 
 
Этот проект представляет собой простой кэширующий DNS-сервер, написанный на языке Python. Он поддерживает типы DNS-запросов A, AAAA и NS. 
Когда сервер получает DNS-запрос, он сначала проверяет свой кэш, чтобы узнать, есть ли у него уже ответ на этот запрос.
Если ответ есть в кэше, сервер немедленно возвращает его клиенту. 
Если ответа в кэше нет, сервер запрашивает запись у вышестоящих DNS-серверов и сохраняет полученный ответ в своем кэше.

работа сервера:
Сервер прослушивает порт 53.
При первом запуске кэш пустой.
Сервер получает рекурсивный запрос от клиента и выполняет разрешение запроса.
Полученный ответ разбирается, и из него извлекается вся полезная информация, включая записи из полей Authority и Additional.
Полученная информация сохраняется в кэше сервера, который может быть реализован, например, в виде двух хэш-массивов, где один массив хранит соответствие доменных имён и IP-адресов, а другой IP-адресов и доменных имён.
Сервер регулярно просматривает кэш и удаляет просроченные записи, используя поле TTL.
Сервер не теряет работоспособность, если старший сервер не ответил на запрос, так как обрабатывает это событие и продолжает работу.
При штатном выключении сервер сериализует данные из кэша и сохраняет их на диск.
При повторных запусках сервер считывает данные с диска, удаляет просроченные записи и инициализирует кэш.

запуск:
запустить файл dns_server_cache
потом в cmd ввести
nslookup
server 127.0.0.1
затем ввести сайт, к которому хотим обратиться, например: vk.com

примеры использования:

![708a58a2-a1d1-4739-9b91-b547f320e7f7](https://github.com/ALEXEY-PEREVOSHCHIKOV/cache_DNS_SERVER_/assets/114176011/c64fef5c-51f4-43ca-9228-0c561e4e9ca2)

![14d4dbfd-a1fa-438c-b981-48da351d1a46](https://github.com/ALEXEY-PEREVOSHCHIKOV/cache_DNS_SERVER_/assets/114176011/f39d7106-9c28-4269-a126-2a331f2d7069)

![8362175e-984d-4118-bec7-edb241cc370c](https://github.com/ALEXEY-PEREVOSHCHIKOV/cache_DNS_SERVER_/assets/114176011/49d3942c-34c3-4577-b004-82324da0370f)

![image](https://github.com/ALEXEY-PEREVOSHCHIKOV/cache_DNS_SERVER_/assets/114176011/3e10476d-7567-4198-b1bd-d0de0fe866a5)
