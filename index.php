<?php
// ======================================
// CONFIGURACIÓN INICIAL (SEGURIDAD/SESIONES)
// ======================================

// Configuración de ejecución
set_time_limit(30);
ini_set('memory_limit', '128M');
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__.'/php-errors.log');

// Verificar requisitos
if (!function_exists('json_decode')) {
    die("Error: Extensión JSON no está instalada");
}

// Configuración de seguridad HTTP
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Configuración de sesión segura
$isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;

if (!file_exists(__DIR__.'/sessions')) {
    mkdir(__DIR__.'/sessions', 0755);
}

session_start([
    'cookie_lifetime' => 86400,
    'cookie_secure' => $isSecure,
    'cookie_httponly' => true,
    'use_strict_mode' => true,
    'cookie_samesite' => 'Lax',
    'save_path' => __DIR__.'/sessions'
]);

// ======================================
// CONFIGURACIÓN GENERAL
// ======================================
$uploads_dir = "uploads/";
$allowed_image_types = ['jpg', 'jpeg', 'png', 'gif'];
$max_file_size = 5 * 1024 * 1024;
$google_maps_api_key = "AIzaSyDt_rhgIYlQ1EtpUGUv6j0R3InUzmwD3EE";
$data_dir = "data/";

// Crear directorios con verificación
if (!file_exists($data_dir)) {
    if (!mkdir($data_dir, 0755, true)) {
        error_log("No se pudo crear directorio: $data_dir");
        die("Error crítico: No se pudo crear directorio de datos");
    }
    chmod($data_dir, 0755);
}

if (!file_exists($uploads_dir)) {
    if (!mkdir($uploads_dir, 0755, true)) {
        error_log("No se pudo crear directorio: $uploads_dir");
        die("Error crítico: No se pudo crear directorio de uploads");
    }
    chmod($uploads_dir, 0755);
}

$users_file = $data_dir . "users.json";
$controles_file = $data_dir . "controles.json";
$camuflados_file = $data_dir . "camuflados.json";

// ======================================
// FUNCIONES MEJORADAS PARA MANEJO DE JSON
// ======================================

function safe_json_read($file) {
    if (!file_exists($file)) {
        file_put_contents($file, '[]');
        return [];
    }

    $content = @file_get_contents($file);
    if ($content === false) {
        error_log("Error al leer archivo: $file");
        return [];
    }

    $data = @json_decode($content, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        // Intenta reparar JSON corrupto
        $content = preg_replace('/[^\x20-\x7F]/', '', $content);
        $data = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $backup = $file . '.corrupt.' . time();
            rename($file, $backup);
            error_log("JSON corrupto: $file - Backup creado en: $backup");
            file_put_contents($file, '[]');
            return [];
        }
    }
    return is_array($data) ? $data : [];
}

function safe_json_write($file, $data) {
    $temp = tempnam(dirname($file), 'tmp');
    if ($temp === false) {
        error_log("Error al crear archivo temporal para: $file");
        return false;
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        error_log("Error al codificar JSON para: $file");
        unlink($temp);
        return false;
    }

    if (file_put_contents($temp, $json) === false) {
        error_log("Error al escribir en archivo temporal: $temp");
        unlink($temp);
        return false;
    }

    if (!rename($temp, $file)) {
        error_log("Error al renombrar archivo temporal: $temp -> $file");
        unlink($temp);
        return false;
    }

    chmod($file, 0644);
    return true;
}

function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function validateLatLng($lat, $lng) {
    return is_numeric($lat) && is_numeric($lng) &&
           $lat >= -90 && $lat <= 90 &&
           $lng >= -180 && $lng <= 180;
}

function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ======================================
// PROCESAMIENTO DE FORMULARIOS
// ======================================
$error = '';
$success = '';

// Registro de usuario
if (isset($_POST['register'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];
        $telefono = sanitizeInput($_POST['telefono'] ?? '');

        if (strlen($username) < 4 || strlen($username) > 20) {
            $error = "El usuario debe tener entre 4 y 20 caracteres.";
        } elseif (strlen($password) < 8) {
            $error = "La contraseña debe tener al menos 8 caracteres.";
        } else {
            $users = safe_json_read($users_file);

            foreach ($users as $user) {
                if ($user['username'] === $username) {
                    $error = "Usuario ya existe.";
                    break;
                }
            }

            if (empty($error)) {
                $users[] = [
                    'username' => $username,
                    'password' => password_hash($password, PASSWORD_DEFAULT),
                    'telefono' => $telefono,
                    'created_at' => date('Y-m-d H:i:s')
                ];

                if (safe_json_write($users_file, $users)) {
                    $_SESSION['register_success'] = "Registrado correctamente. Inicia sesión.";
                    header("Location: ".$_SERVER['PHP_SELF']);
                    exit;
                } else {
                    $error = "Error al guardar el usuario. Inténtalo de nuevo.";
                }
            }
        }
    }
}

// Mostrar mensaje de éxito de registro si existe
if (isset($_SESSION['register_success'])) {
    $success = $_SESSION['register_success'];
    unset($_SESSION['register_success']);
}

// Inicio de sesión
if (isset($_POST['login'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];

        $users = safe_json_read($users_file);
        $user_found = null;

        foreach ($users as $user) {
            if ($user['username'] === $username) {
                $user_found = $user;
                break;
            }
        }

        if ($user_found && password_verify($password, $user_found['password'])) {
            $_SESSION['username'] = $user_found['username'];
            $_SESSION['last_login'] = time();
            session_regenerate_id(true);
            header("Location: index.php");
            exit;
        } else {
            $error = $user_found ? "Contraseña incorrecta." : "Usuario no encontrado.";
        }
    }
}

// Cierre de sesión
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// Añadir control
if (isset($_POST['guardar_control']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $lat = $_POST['lat'];
        $lng = $_POST['lng'];
        $tipo = $_POST['tipo'] ?? 'otros';
        $descripcion = sanitizeInput($_POST['descripcion'] ?? 'Control reportado');

        if (!validateLatLng($lat, $lng)) {
            $error = "Coordenadas inválidas.";
        } else {
            $controles = safe_json_read($controles_file);

            $controles[] = [
                'lat' => (float)$lat,
                'lng' => (float)$lng,
                'tipo' => $tipo,
                'descripcion' => $descripcion,
                'usuario' => $_SESSION['username'],
                'fecha' => date('Y-m-d H:i:s'),
                'votos' => [],
                'puntuacion' => 0
            ];

            if (safe_json_write($controles_file, $controles)) {
                $success = "Control guardado correctamente.";
            } else {
                $error = "Error al guardar el control.";
            }
        }
    }
}

// Añadir vehículo camuflado
if (isset($_POST['guardar_camuflado']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $matricula = sanitizeInput($_POST['matricula']);
        $marca = sanitizeInput($_POST['marca']);
        $modelo = sanitizeInput($_POST['modelo']);
        $descripcion = sanitizeInput($_POST['descripcion']);
        $foto = '';

        if (empty($matricula) || empty($marca) || empty($modelo)) {
            $error = "Matrícula, marca y modelo son obligatorios.";
        } else {
            if (isset($_FILES['foto']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK) {
                $file_name = $_FILES['foto']['name'];
                $file_tmp = $_FILES['foto']['tmp_name'];
                $file_size = $_FILES['foto']['size'];
                $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));

                if (!in_array($file_ext, $allowed_image_types)) {
                    $error = "Solo se permiten imágenes JPG, JPEG, PNG o GIF.";
                } elseif ($file_size > $max_file_size) {
                    $error = "La imagen es demasiado grande (máximo 5MB).";
                } else {
                    $new_file_name = uniqid('', true) . '.' . $file_ext;
                    $foto = $uploads_dir . $new_file_name;

                    if (!move_uploaded_file($file_tmp, $foto)) {
                        $error = "Error al subir la imagen.";
                        $foto = '';
                    }
                }
            }

            if (empty($error)) {
                $camuflados = safe_json_read($camuflados_file);

                $camuflados[] = [
                    'matricula' => $matricula,
                    'marca' => $marca,
                    'modelo' => $modelo,
                    'descripcion' => $descripcion,
                    'foto' => $foto,
                    'usuario' => $_SESSION['username'],
                    'fecha' => date('Y-m-d H:i:s')
                ];

                if (safe_json_write($camuflados_file, $camuflados)) {
                    $success = "Vehículo camuflado guardado correctamente.";
                } else {
                    $error = "Error al guardar el vehículo.";
                }
            }
        }
    }
}

// Procesar votos
if (isset($_POST['votar']) && isset($_SESSION['username'])) {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Token CSRF inválido.";
    } else {
        $control_id = (int)$_POST['control_id'];
        $voto = (int)$_POST['voto'];

        $controles = safe_json_read($controles_file);

        if (isset($controles[$control_id])) {
            if (!isset($controles[$control_id]['votos'])) {
                $controles[$control_id]['votos'] = [];
            }

            $controles[$control_id]['votos'][$_SESSION['username']] = $voto;

            $total_votos = count($controles[$control_id]['votos']);
            $suma_votos = array_sum($controles[$control_id]['votos']);
            $controles[$control_id]['puntuacion'] = $total_votos > 0 ? $suma_votos / $total_votos : 0;

            if (safe_json_write($controles_file, $controles)) {
                $success = "Voto registrado correctamente.";
            } else {
                $error = "Error al guardar el voto.";
            }
        }
    }
}

// Cargar datos para mostrar
$controles = safe_json_read($controles_file);
$camuflados = safe_json_read($camuflados_file);

// Generar token CSRF
$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Radar VTC</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
    <style>
        body { background: #f8f9fa; font-family: 'Segoe UI', sans-serif; }
        .container { margin-top: 30px; }
        #map { height: 600px; margin-bottom: 20px; border: 2px solid #ddd; border-radius: 5px; }
        .big-button { font-size: 1.5rem; padding: 15px 25px; background-color: #dc3545; color: white;
                     border: none; border-radius: 8px; display: block; width: 100%; margin-bottom: 20px; }
        .card { margin-bottom: 20px; }
        footer { margin-top: 40px; padding: 20px; text-align: center; font-size: 0.9rem; color: #999; }
        img.preview { max-width: 200px; max-height: 200px; margin-top: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .error { color: #dc3545; }
        .success { color: #28a745; }
        .heatmap-layer { opacity: 0.7; }
        .voting-buttons { margin-top: 10px; }
        .voting-buttons button { margin-right: 5px; }
        .control-details { margin-top: 10px; font-size: 0.9em; }
        .control-type { display: inline-block; padding: 2px 6px; border-radius: 3px;
                       font-size: 0.8em; font-weight: bold; margin-right: 5px; }
        .gm-style .gm-style-iw-c { padding: 12px !important; max-width: 300px !important; }
        .gm-style .gm-style-iw-d { overflow: auto !important; }
        #addControlModal .modal-dialog { max-width: 500px; }
        #addControlModal .map-container { height: 250px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 5px; }
        #miniMap { height: 100%; width: 100%; }
        .address-display { background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .address-line { margin-bottom: 5px; }
        #addressSearch { margin-bottom: 10px; }
        #searchResults { max-height: 150px; overflow-y: auto; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; display: none; }
        .search-result-item { padding: 8px; cursor: pointer; border-bottom: 1px solid #eee; }
        .search-result-item:hover { background-color: #f0f0f0; }
    </style>
</head>
<body>
<div class="container">
    <h1 class="text-center mb-4">Radar VTC</h1>

    <?php if (!isset($_SESSION['username'])): ?>
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($success)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h3 class="card-title">Registro</h3>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <div class="mb-3">
                                <label for="reg-username" class="form-label">Usuario</label>
                                <input type="text" id="reg-username" name="username" class="form-control" required minlength="4" maxlength="20">
                            </div>
                            <div class="mb-3">
                                <label for="reg-password" class="form-label">Contraseña</label>
                                <input type="password" id="reg-password" name="password" class="form-control" required minlength="8">
                            </div>
                            <div class="mb-3">
                                <label for="telefono" class="form-label">Teléfono (opcional)</label>
                                <input type="tel" id="telefono" name="telefono" class="form-control" placeholder="+525511223344">
                            </div>
                            <button type="submit" name="register" class="btn btn-primary w-100">Registrarse</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h3 class="card-title">Inicio de Sesión</h3>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <div class="mb-3">
                                <label for="login-username" class="form-label">Usuario</label>
                                <input type="text" id="login-username" name="username" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label for="login-password" class="form-label">Contraseña</label>
                                <input type="password" id="login-password" name="password" class="form-control" required>
                            </div>
                            <button type="submit" name="login" class="btn btn-success w-100">Iniciar Sesión</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    <?php else: ?>
        <div class="text-end mb-3">
            Bienvenido <strong><?= htmlspecialchars($_SESSION['username']) ?></strong> |
            <a href="?logout">Cerrar sesión</a>
        </div>

        <button onclick="reportarUbicacion()" class="big-button">REPORTAR CONTROL EN MI UBICACIÓN ACTUAL</button>

        <div id="map"></div>

        <!-- Modal para añadir control -->
        <div class="modal fade" id="addControlModal" tabindex="-1" aria-labelledby="addControlModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="addControlModalLabel">Añadir Nuevo Control</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <form method="POST" id="addControlForm">
                        <div class="modal-body">
                            <div class="mb-3">
                                <input type="text" id="addressSearch" class="form-control" placeholder="Buscar dirección...">
                                <div id="searchResults"></div>
                            </div>

                            <div class="map-container">
                                <div id="miniMap"></div>
                            </div>

                            <div class="address-display">
                                <div class="address-line"><strong>Calle:</strong> <span id="address-street"></span></div>
                                <div class="address-line"><strong>Número:</strong> <span id="address-number"></span></div>
                                <div class="address-line"><strong>Ciudad:</strong> <span id="address-city"></span></div>
                                <div class="address-line"><strong>Código Postal:</strong> <span id="address-postal"></span></div>
                            </div>

                            <input type="hidden" name="lat" id="modalLatInput">
                            <input type="hidden" name="lng" id="modalLngInput">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

                            <div class="mb-3">
                                <label for="modalTipo" class="form-label">Tipo de control</label>
                                <select id="modalTipo" name="tipo" class="form-control" required>
                                    <option value="radar">Radar</option>
                                    <option value="policia">Control policial</option>
                                    <option value="dgt">Control DGT</option>
                                    <option value="otros">Otro tipo</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="modalDescripcion" class="form-label">Descripción (opcional)</label>
                                <input type="text" id="modalDescripcion" name="descripcion" class="form-control">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                            <button type="submit" name="guardar_control" class="btn btn-primary">Guardar Control</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Formulario para añadir coche camuflado -->
        <div class="card p-3">
            <h5>Añadir vehículo camuflado</h5>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                <div class="mb-3">
                    <label for="matricula" class="form-label">Matrícula</label>
                    <input type="text" id="matricula" name="matricula" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="marca" class="form-label">Marca</label>
                    <input type="text" id="marca" name="marca" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="modelo" class="form-label">Modelo</label>
                    <input type="text" id="modelo" name="modelo" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="descripcion" class="form-label">Descripción</label>
                    <textarea id="descripcion" name="descripcion" class="form-control"></textarea>
                </div>
                <div class="mb-3">
                    <label for="foto" class="form-label">Foto (opcional, max 5MB)</label>
                    <input type="file" id="foto" name="foto" class="form-control" accept="image/jpeg,image/png,image/gif">
                </div>
                <button type="submit" name="guardar_camuflado" class="btn btn-dark">Guardar coche camuflado</button>
            </form>
        </div>

        <!-- Listado de controles -->
        <h3 class="mt-5">Controles Reportados</h3>
        <?php if (empty($controles)): ?>
            <div class="alert alert-info">No hay controles reportados aún.</div>
        <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
                <?php foreach ($controles as $index => $c): ?>
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title">Control #<?= $index + 1 ?></h5>
                                <div class="control-type" style="background-color: <?=
                                    $c['tipo'] === 'radar' ? '#FF000020' :
                                    ($c['tipo'] === 'policia' ? '#0000FF20' :
                                    ($c['tipo'] === 'dgt' ? '#FFA50020' : '#80808020')) ?>;
                                    color: <?=
                                    $c['tipo'] === 'radar' ? '#FF0000' :
                                    ($c['tipo'] === 'policia' ? '#0000FF' :
                                    ($c['tipo'] === 'dgt' ? '#FFA500' : '#808080')) ?>">
                                    <?=
                                    $c['tipo'] === 'radar' ? 'Radar' :
                                    ($c['tipo'] === 'policia' ? 'Control policial' :
                                    ($c['tipo'] === 'dgt' ? 'Control DGT' : 'Otro control')) ?>
                                </div>
                                <p class="card-text"><?= htmlspecialchars($c['descripcion']) ?></p>
                                <div class="control-details">
                                    <strong>Reportado por:</strong> <?= htmlspecialchars($c['usuario']) ?><br>
                                    <strong>Fecha:</strong> <?= htmlspecialchars($c['fecha']) ?><br>
                                    <strong>Puntuación:</strong> <?= number_format($c['puntuacion'] ?? 0, 1) ?>
                                    (<?= count($c['votos'] ?? []) ?> votos)
                                </div>
                                <?php if (isset($_SESSION['username'])): ?>
                                <div class="voting-buttons mt-3">
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                        <input type="hidden" name="control_id" value="<?= $index ?>">
                                        <button type="submit" name="votar" value="1" class="btn btn-sm btn-success">👍</button>
                                        <button type="submit" name="votar" value="0" class="btn btn-sm btn-secondary">➖</button>
                                        <button type="submit" name="votar" value="-1" class="btn btn-sm btn-danger">👎</button>
                                    </form>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <!-- Listado de coches camuflados -->
        <h3 class="mt-5">Vehículos Camuflados</h3>
        <?php if (empty($camuflados)): ?>
            <div class="alert alert-info">No hay vehículos camuflados reportados aún.</div>
        <?php else: ?>
            <div class="row row-cols-1 row-cols-md-2 g-4">
                <?php foreach ($camuflados as $c): ?>
                    <div class="col">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title"><?= htmlspecialchars($c['marca']) ?> <?= htmlspecialchars($c['modelo']) ?></h5>
                                <h6 class="card-subtitle mb-2 text-muted"><?= htmlspecialchars($c['matricula']) ?></h6>
                                <?php if (!empty($c['descripcion'])): ?>
                                    <p class="card-text"><?= htmlspecialchars($c['descripcion']) ?></p>
                                <?php endif; ?>
                                <div class="control-details">
                                    <strong>Reportado por:</strong> <?= htmlspecialchars($c['usuario']) ?><br>
                                    <strong>Fecha:</strong> <?= htmlspecialchars($c['fecha']) ?>
                                </div>
                                <?php if (!empty($c['foto'])): ?>
                                    <img src="<?= htmlspecialchars($c['foto']) ?>" class="preview mt-3" alt="Foto del vehículo">
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<footer class="mt-5">
    Radar VTC © <?= date('Y') ?> |
    <a href="#" data-bs-toggle="modal" data-bs-target="#aboutModal">Acerca de</a>
</footer>

<!-- Modal Acerca de -->
<div class="modal fade" id="aboutModal" tabindex="-1" aria-labelledby="aboutModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="aboutModalLabel">Acerca de Radar VTC</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Aplicación para reportar controles de tráfico y vehículos camuflados.</p>
                <p><strong>Versión:</strong> 2.0</p>
                <p><strong>Desarrollado por:</strong> TuNombre</p>
                <p>Esta aplicación utiliza Google Maps API para mostrar la ubicación de los controles.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
<script src="https://maps.googleapis.com/maps/api/js?key=<?= $google_maps_api_key ?>&libraries=places,visualization&callback=initMap" async defer></script>

<script>
    // Variables globales
    let map, heatmap, userMarker, controlsMarkers = [], addControlMarker, miniMap, geocoder, placesService, autocomplete;
    const controlTypes = {
        'radar': {color: '#FF0000', name: 'Radar'},
        'policia': {color: '#0000FF', name: 'Control policial'},
        'dgt': {color: '#FFA500', name: 'Control DGT'},
        'otros': {color: '#808080', name: 'Otro control'}
    };

    // Función para inicializar el mapa
    function initMap() {
        const initialPos = {lat: 40.4168, lng: -3.7038};

        map = new google.maps.Map(document.getElementById('map'), {
            center: initialPos,
            zoom: 14,
            streetViewControl: false,
            mapTypeControlOptions: {mapTypeIds: ['roadmap', 'hybrid']}
        });

        geocoder = new google.maps.Geocoder();
        placesService = new google.maps.places.PlacesService(map);

        map.addListener('click', (event) => {
            openAddControlModal(event.latLng);
            updateAddressFromLatLng(event.latLng);
        });

        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                position => {
                    const userPos = {
                        lat: position.coords.latitude,
                        lng: position.coords.longitude
                    };

                    map.setCenter(userPos);

                    userMarker = new google.maps.Marker({
                        position: userPos,
                        map: map,
                        title: 'Tu ubicación',
                        icon: {
                            path: google.maps.SymbolPath.CIRCLE,
                            scale: 8,
                            fillColor: '#4285F4',
                            fillOpacity: 1,
                            strokeWeight: 2,
                            strokeColor: '#FFFFFF'
                        }
                    });

                    loadControls();
                },
                error => {
                    console.error("Error al obtener ubicación:", error);
                    loadControls();
                },
                {enableHighAccuracy: true, timeout: 5000}
            );
        } else {
            alert("Tu navegador no soporta geolocalización.");
            loadControls();
        }
    }

    // Función para cargar controles en el mapa
    function loadControls() {
        const controles = <?= json_encode($controles, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
        const heatmapData = [];

        controlsMarkers.forEach(marker => marker.setMap(null));
        controlsMarkers = [];

        controles.forEach((control, index) => {
            const controlType = control.tipo || 'otros';
            const typeInfo = controlTypes[controlType] || controlTypes['otros'];
            const position = {lat: parseFloat(control.lat), lng: parseFloat(control.lng)};

            const marker = new google.maps.Marker({
                position: position,
                map: map,
                title: control.descripcion,
                icon: {
                    path: google.maps.SymbolPath.CIRCLE,
                    scale: 8,
                    fillColor: typeInfo.color,
                    fillOpacity: 1,
                    strokeWeight: 2,
                    strokeColor: '#FFFFFF'
                }
            });

            getAddressForControl(position, (address) => {
                const infoWindow = new google.maps.InfoWindow({
                    content: createControlInfoContent(control, index, typeInfo, address)
                });

                marker.addListener('click', () => {
                    infoWindow.open(map, marker);
                });
            });

            controlsMarkers.push(marker);
            heatmapData.push({
                location: new google.maps.LatLng(control.lat, control.lng),
                weight: (control.puntuacion || 0) + 1
            });
        });

        if (heatmap) {
            heatmap.setData(heatmapData);
        } else {
            heatmap = new google.maps.visualization.HeatmapLayer({
                data: heatmapData,
                map: map,
                radius: 30,
                opacity: 0.7,
                gradient: [
                    'rgba(0, 255, 0, 0)',
                    'rgba(0, 255, 0, 1)',
                    'rgba(255, 255, 0, 1)',
                    'rgba(255, 165, 0, 1)',
                    'rgba(255, 0, 0, 1)'
                ]
            });
        }
    }

    // Función para obtener dirección de un control
    function getAddressForControl(position, callback) {
        geocoder.geocode({location: position}, (results, status) => {
            if (status === 'OK' && results[0]) {
                let street = '', number = '', city = '';

                for (const component of results[0].address_components) {
                    const componentType = component.types[0];

                    switch (componentType) {
                        case 'route': street = component.long_name; break;
                        case 'street_number': number = component.long_name; break;
                        case 'locality': city = component.long_name; break;
                    }
                }

                callback({
                    street: street || 'Calle no especificada',
                    number: number || 'S/N',
                    city: city || 'Ciudad no especificada'
                });
            } else {
                callback({
                    street: 'Dirección no disponible',
                    number: '',
                    city: ''
                });
            }
        });
    }

    // Función para crear el contenido de la ventana de información
    function createControlInfoContent(control, index, typeInfo, address) {
        const rating = control.puntuacion ? control.puntuacion.toFixed(1) : 'Sin votos';
        const totalVotes = control.votos ? Object.keys(control.votos).length : 0;

        return `
            <div class="control-info">
                <h5>${typeInfo.name}</h5>
                <div class="control-type" style="background-color: ${typeInfo.color}20; color: ${typeInfo.color}">
                    ${typeInfo.name}
                </div>
                <p>${escapeHtml(control.descripcion)}</p>
                <div class="control-details">
                    <strong>Ubicación:</strong> ${address.street} ${address.number}, ${address.city}<br>
                    <strong>Reportado por:</strong> ${escapeHtml(control.usuario)}<br>
                    <strong>Fecha:</strong> ${escapeHtml(control.fecha)}<br>
                    <strong>Puntuación:</strong> ${rating} (${totalVotes} votos)
                </div>
                <?php if (isset($_SESSION['username'])): ?>
                <div class="voting-buttons">
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="control_id" value="${index}">
                        <button type="submit" name="votar" value="1" class="btn btn-sm btn-success">👍</button>
                        <button type="submit" name="votar" value="0" class="btn btn-sm btn-secondary">➖</button>
                        <button type="submit" name="votar" value="-1" class="btn btn-sm btn-danger">👎</button>
                    </form>
                </div>
                <?php endif; ?>
            </div>
        `;
    }

    // Función para abrir el modal de añadir control
    function openAddControlModal(latLng) {
        const modal = new bootstrap.Modal(document.getElementById('addControlModal'));
        modal.show();

        if (!miniMap) {
            miniMap = new google.maps.Map(document.getElementById('miniMap'), {
                center: latLng,
                zoom: 18,
                disableDefaultUI: true
            });

            addControlMarker = new google.maps.Marker({
                position: latLng,
                map: miniMap,
                draggable: true,
                title: 'Ubicación del control'
            });

            addControlMarker.addListener('dragend', function(event) {
                updateAddressFromLatLng(event.latLng);
            });

            initAutocomplete();
        } else {
            miniMap.setCenter(latLng);
            addControlMarker.setPosition(latLng);
        }

        document.getElementById('modalLatInput').value = latLng.lat();
        document.getElementById('modalLngInput').value = latLng.lng();
    }

    // Función para inicializar el autocompletado de direcciones
    function initAutocomplete() {
        const input = document.getElementById('addressSearch');
        autocomplete = new google.maps.places.Autocomplete(input, {
            types: ['address'],
            componentRestrictions: {country: 'es'}
        });

        autocomplete.addListener('place_changed', () => {
            const place = autocomplete.getPlace();
            if (!place.geometry) {
                alert("No se encontraron detalles para esta dirección");
                return;
            }

            miniMap.setCenter(place.geometry.location);
            addControlMarker.setPosition(place.geometry.location);
            document.getElementById('modalLatInput').value = place.geometry.location.lat();
            document.getElementById('modalLngInput').value = place.geometry.location.lng();
            updateAddressFromPlace(place);
        });
    }

    // Función para actualizar la dirección desde un lugar
    function updateAddressFromPlace(place) {
        let street = '', number = '', city = '', postalCode = '';

        for (const component of place.address_components) {
            const componentType = component.types[0];

            switch (componentType) {
                case 'route': street = component.long_name; break;
                case 'street_number': number = component.long_name; break;
                case 'locality': city = component.long_name; break;
                case 'postal_code': postalCode = component.long_name; break;
            }
        }

        document.getElementById('address-street').textContent = street || 'No especificada';
        document.getElementById('address-number').textContent = number || 'S/N';
        document.getElementById('address-city').textContent = city || 'No especificada';
        document.getElementById('address-postal').textContent = postalCode || 'No especificado';
    }

    // Función para actualizar la dirección desde coordenadas
    function updateAddressFromLatLng(latLng) {
        geocoder.geocode({location: latLng}, (results, status) => {
            if (status === 'OK' && results[0]) {
                updateAddressFromPlace(results[0]);
            } else {
                console.error('Geocoder falló debido a: ' + status);
                document.getElementById('address-street').textContent = 'No se pudo determinar';
                document.getElementById('address-number').textContent = 'N/A';
                document.getElementById('address-city').textContent = 'No se pudo determinar';
                document.getElementById('address-postal').textContent = 'N/A';
            }
        });
    }

    // Función para reportar ubicación actual
    function reportarUbicacion() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                pos => {
                    const latLng = new google.maps.LatLng(
                        pos.coords.latitude,
                        pos.coords.longitude
                    );
                    openAddControlModal(latLng);
                    updateAddressFromLatLng(latLng);
                },
                err => {
                    alert("No se pudo obtener la ubicación. Asegúrate de haber permitido el acceso a la ubicación.");
                },
                {enableHighAccuracy: true}
            );
        } else {
            alert("Tu navegador no soporta geolocalización.");
        }
    }

    // Función para escapar HTML
    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Mostrar notificaciones
    <?php if ($success): ?>
        Toastify({
            text: "<?= addslashes($success) ?>",
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "#28a745",
        }).showToast();
    <?php endif; ?>

    <?php if ($error): ?>
        Toastify({
            text: "<?= addslashes($error) ?>",
            duration: 3000,
            close: true,
            gravity: "top",
            position: "right",
            backgroundColor: "#dc3545",
        }).showToast();
    <?php endif; ?>
</script>
</body>
</html>
