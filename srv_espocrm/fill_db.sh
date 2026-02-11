#!/bin/bash

# Конфигурация
DB_CONTAINER="srv_espocrm_db"
DB_USER="espocrm"
DB_PASS="espocrm"
DB_NAME="espocrm"
DB_HOST="srv_espocrm_db"

# Массивы для данных
first_names=("Иван" "Петр" "Алексей" "Мария" "Анна" "Дмитрий" "Елена" "Сергей" "Ольга" "Игорь")
last_names=("Смирнов" "Иванов" "Кузнецов" "Попов" "Васильев" "Петров" "Соколов" "Михайлов" "Новиков" "Федоров")
cities=("Москва" "Санкт-Петербург" "Новосибирск" "Екатеринбург" "Казань")
streets=("Ленина" "Пушкина" "Садовая" "Лесная" "Новая")
countries=("Россия" "Беларусь" "Казахстан")
domains=("gmail.com" "mail.ru" "yandex.ru" "company.com")

# Функция для выполнения SQL запросов
execute_sql() {
    local sql="$1"
    mariadb --host="$DB_HOST" --user="$DB_USER" --password="$DB_PASS" --default-character-set=utf8mb4 "$DB_NAME" -e "$sql"
}

# Функция проверки существования таблицы
check_table_exists() {
    local table_exists=$(execute_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$DB_NAME' AND table_name = 'contact';" 2>/dev/null | tail -1)
    
    if [ "$table_exists" -eq 1 ]; then
        echo "✓ Таблица contact существует"
        return 0
    else
        echo "✗ Таблица contact не найдена"
        return 1
    fi
}

# Функция создания таблицы
create_table() {
    echo "Создание таблицы contact..."
    
    SQL_CREATE="CREATE TABLE IF NOT EXISTS contact (
        id VARCHAR(24) NOT NULL PRIMARY KEY,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        deleted TINYINT(1) DEFAULT 0,
        description TEXT,
        address_street VARCHAR(255),
        address_city VARCHAR(255),
        address_country VARCHAR(255),
        address_postal_code VARCHAR(20),
        created_at DATETIME,
        modified_at DATETIME,
        INDEX idx_deleted (deleted)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
    
    execute_sql "$SQL_CREATE"
    
    if [ $? -eq 0 ]; then
        echo "✓ Таблица contact создана"
        return 0
    else
        echo "✗ Ошибка при создании таблицы"
        return 1
    fi
}

# Функция очистки таблицы
clear_table() {
    echo "Очистка таблицы contact..."
    execute_sql "TRUNCATE TABLE contact;"
    
    if [ $? -eq 0 ]; then
        echo "✓ Таблица очищена"
        return 0
    else
        echo "✗ Ошибка при очистке таблицы"
        return 1
    fi
}

# Функция наполнения таблицы данными
fill_table() {
    echo "Формирование SQL-запроса с адресами и контактами..."
    
    # Начало транзакции для ускорения вставки
    SQL_QUERY="START TRANSACTION;"
    
    # 1. Вставка записи ID=1
    SQL_QUERY+="INSERT INTO contact (id, first_name, last_name, deleted, description, address_street, address_city, address_country, address_postal_code, created_at, modified_at) VALUES "
    SQL_QUERY+="('1', 'Test', 'Test', 0, 'Тестовая запись. Тел: +79001112233. Email: admin@espocrm.local', 'ул. Тестовая, 1', 'Москва', 'РФ', '101000', NOW(), NOW())"
    
    # 2. Генерация 50 записей
    for i in {2..51}
    do
        f_name=${first_names[$RANDOM % 10]}
        l_name=${last_names[$RANDOM % 10]}
        if [[ "$f_name" == "Мария" || "$f_name" == "Анна" || "$f_name" == "Елена" || "$f_name" == "Ольга" ]]; then
            l_name="${l_name}а"
        fi
        city=${cities[$RANDOM % 5]}
        street="ул. ${streets[$RANDOM % 5]}, д. $((RANDOM % 100 + 1))"
        country=${countries[$RANDOM % 3]}
        zip=$((RANDOM % 899999 + 100000))
        
        # Контактные данные для описания
        phone="+7911$((RANDOM % 8999999 + 1000000))"
        email="user_$i@${domains[$RANDOM % 4]}"
        desc="Тел: $phone. Email: $email."
        
        # Случайное время создания (до 30 дней назад)
        rand_hours=$((RANDOM % 720))

        SQL_QUERY+=", ('$i', '$f_name', '$l_name', 0, '$desc', '$street', '$city', '$country', '$zip', TIMESTAMPADD(HOUR, -$rand_hours, NOW()), NOW())"
    done
    
    SQL_QUERY+="; COMMIT;"
    
    echo "Отправка данных в контейнер $DB_CONTAINER..."
    
    # Выполнение с явным указанием кодировки
    execute_sql "$SQL_QUERY"
    
    if [ $? -eq 0 ]; then
        echo "=== Успешно! База наполнена расширенными данными ==="
        echo "Всего записей: 51"
        echo "Кодировка: UTF-8"
        echo "Поля: id, name, address, description (phone/email)"
        echo "--------------------------------------------------"
        
        # Проверка случайной записи
        execute_sql "SELECT id, first_name, last_name, address_city, description FROM contact WHERE id='10' LIMIT 1;"
        
        # Общая статистика
        echo "--------------------------------------------------"
        execute_sql "SELECT COUNT(*) as 'Всего записей', MIN(created_at) as 'Первая запись', MAX(created_at) as 'Последняя запись' FROM contact;"
        
        return 0
    else
        echo "✗ Ошибка при вставке данных"
        return 1
    fi
}

# Основной процесс
main() {
    echo "=================================================="
    echo "Загрузка данных клиентов для EspoCRM"
    echo "База данных: $DB_NAME на сервере $DB_HOST"
    echo "=================================================="
    
    # Проверка подключения к базе
    echo "Проверка подключения к базе данных..."
    if execute_sql "SELECT 1;" > /dev/null 2>&1; then
        echo "✓ Подключение к базе успешно"
    else
        echo "✗ Ошибка подключения к базе данных"
        echo "Проверьте:"
        echo "1. Контейнер $DB_CONTAINER запущен"
        echo "2. Параметры подключения верны"
        echo "3. Сетевые настройки docker"
        exit 1
    fi
    
    # Проверка/создание таблицы
    if check_table_exists; then
        clear_table || exit 1
    else
        create_table || exit 1
    fi
    
    # Наполнение таблицы данными
    fill_table || exit 1
    
    echo "=================================================="
    echo "Данные клиентов успешно загружены!"
    echo "=================================================="
}

# Запуск основного процесса
main
