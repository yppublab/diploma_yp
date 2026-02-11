<?php
// Логика обработки запроса
$message = "";
$db_result = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_key = $_POST['api_key'] ?? '';
    $client_id = $_POST['client_id'] ?? '';

    // 1. Читаем файл с секретом
    $secret_path = '/tmp/secret.txt';
    $server_secret = file_exists($secret_path) ? trim(file_get_contents($secret_path)) : null;

    if (!$server_secret) {
        $message = "Ошибка: Файл секрета не найден на сервере.";
    } elseif ($input_key === $server_secret) {
        $message = "Ключ подтвержден. Доступ разрешен.";

        // 2. Работа с БД
        if (!empty($client_id)) {
            $db_host = 'srv_espocrm_db'; 
            $db_user = 'espocrm';
            $db_pass = 'espocrm';
            $db_name = 'espocrm';

            try {
                $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
                
                // Тут нужна фильтрация запроса, но лень переписывать, у нас итак на фронте фильтр есть
                // Это позволяет провести SQL-injection типа: 1' OR '1'='1
                $sql = "SELECT id, first_name, last_name, deleted, description, address_street, address_city, address_country, address_postal_code, created_at, modified_at FROM contact WHERE id = '$client_id'";
                $result = $conn->query($sql);

                if ($result && $result->num_rows > 0) {
                    $db_result = "Найдено записей: " . $result->num_rows . "<br>";
                    while ($row = $result->fetch_assoc()) {
                        $db_result .= "• " .  htmlspecialchars($row['id']) . " " . htmlspecialchars($row['first_name']) . " " . htmlspecialchars($row['last_name']) . " " . htmlspecialchars($row['description']) . " " . htmlspecialchars($row['address_country']) . " " . htmlspecialchars($row['address_street']) . " " . htmlspecialchars($row['address_city']) . " " . htmlspecialchars($row['created_at']) . " " . htmlspecialchars($row['modified_at']) . "<br>";
                    }
                } else {
                    $db_result = "Данные не найдены.";
                }
                $conn->close();
            } catch (Exception $e) {
                $db_result = "Ошибка БД: " . $e->getMessage();
            }
        }
    } else {
        $message = "Ошибка: Неверный API ключ.";
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Localhost Development: API Terminal</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #dfe6e9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #2d3436; padding: 2rem; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); width: 450px; }
        h1 { color: #00d2d3; text-align: center; font-size: 1.5rem; }
        label { display: block; margin: 15px 0 5px; font-size: 0.8rem; color: #8395a7; }
        input { width: 100%; padding: 10px; background: #353b48; border: 1px solid #57606f; border-radius: 5px; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 10px; margin-top: 20px; background: #00d2d3; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; }
        .status-box { margin-top: 20px; padding: 15px; border-radius: 5px; font-size: 0.9rem; background: #3b3b3b; border-left: 4px solid #00d2d3; }
        .error { color: #ff7675; border-left-color: #ff7675; }
    </style>
</head>
<body>

<div class="container">
    <h1>Internal API Handler</h1>
    
    <!-- JS Проверка: на ограничение, ввода id в html, ну а кто тут еще будет перехватывать запросы... -->
    <form method="POST" onsubmit="return validateClient()">
        <label>API KEY</label>
        <input type="password" name="api_key" required>

        <label>CLIENT ID (Доступ к тестовым данным по ID: 1)</label>
        <input type="text" name="client_id" id="client_id" required>

        <button type="submit">Выполнить запрос</button>
    </form>

    <script>
        function validateClient() {
            const id = document.getElementById('client_id').value;
            if (id !== '1') {
                alert("Доступ запрещен! Доступны только тестовые данные.");
                return false;
            }
            return true;
        }
    </script>

    <?php if ($message || $db_result): ?>
        <div class="status-box <?= (strpos($message, 'Ошибка') !== false || strpos($db_result, 'Ошибка') !== false) ? 'error' : '' ?>">
            <div><?= $message ?></div>
            <?php if ($db_result): ?>
                <div style="margin-top: 10px; border-top: 1px solid #444; padding-top: 10px;">
                    <?= $db_result ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

</body>
</html>
