<?php
require './config/db.php';

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Roteamento
switch ($method) {
    case 'GET':
        if ($uri === '/api-users/users') {
            $stmt = $conn->prepare("SELECT id, name, email FROM users");
            $stmt->execute();
            $result = $stmt->get_result();

            $users = [];
            while ($row = $result->fetch_assoc()) {
                $users[] = [
                    "id" => $row['id'],
                    "name" => $row['name'],
                    "email" => $row['email']
                ];
            }

            echo json_encode($users);
        }
        break;

    case 'POST':
        if ($uri === '/api-auth/users') {
            // Dados enviados do corpo da requisição
            $input = json_decode(file_get_contents('php://input'), true);

            if (isset($input['email']) && isset($input['password']) && isset($input['name'])) {
                $email = $input['email'];
                $name = $input['name'];
                $password = $input['password'];

                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    echo json_encode(["message" => "Email already registered."]);
                } 
                else {
                    $stmt = $conn->prepare("INSERT INTO users (email, name, password) VALUES (?, ?, ?)");
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt->bind_param("sss", $name, $email, $passwordHash);

                    if ($stmt->execute()) {
                        echo json_encode(["message" => "User created successfully."]);
                    } else {
                        echo json_encode(["message" => "Error creating user."]);
                    }
                }
            } else {
                echo json_encode(["message" => "Name, email and password are required."]);
            }
        }
        break;

    default:
        echo json_encode(["message" => "Method not allowed."]);
        break;
}
