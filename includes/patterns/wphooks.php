<?php
if (!defined('ABSPATH')) exit;

// Login hooks
add_action('wp_login', fn($login, $user) =>
    // Successful login
    wpauditor_log_event('LOGIN_SUCCESS', "user=$login", ['category' => 'AUTH'])
, 10, 2);

add_action('wp_login_failed', function($username) {
    // Failed login + brute-force check
    $ip = wpauditor_get_client_ip();
    wpauditor_log_event('LOGIN_FAILED', "user=$username", ['category' => 'AUTH']);

});

// User hooks
add_action('user_register', fn($id) =>
    // New user created
    wpauditor_log_event('USER_REGISTER', "user=" . get_userdata($id)->user_login, ['category' => 'USER'])
);

add_action('set_user_role', fn($id, $role) =>
    // Role changed
    wpauditor_log_event('ROLE_CHANGE', "user=" . get_userdata($id)->user_login . " new_role=$role", ['category' => 'USER'])
, 10, 2);

add_action('delete_user', fn($id) =>
    // User deleted
    wpauditor_log_event('USER_DELETED', "user=" . get_userdata($id)?->user_login ?? '', ['category' => 'USER'])
);

add_action('profile_update', fn($id) =>
    // Profile updated
    wpauditor_log_event('PROFILE_UPDATED', "user=" . get_userdata($id)?->user_login ?? '', ['category' => 'USER'])
);

// Media hooks
add_action('add_attachment', fn($id) =>
    // Media uploaded
    wpauditor_log_event('MEDIA_UPLOADED', "file=" . get_post($id)->post_title, ['category' => 'MEDIA'])
);

add_action('delete_attachment', fn($id) =>
    // Media deleted
    wpauditor_log_event('MEDIA_DELETED', "file=" . get_post($id)->post_title, ['category' => 'MEDIA'])
);

// Plugin/theme hooks
add_action('activated_plugin', fn($p) =>
    // Plugin activated
    wpauditor_log_event('PLUGIN_ACTIVATED', "plugin=$p", ['category' => 'PLUGIN'])
);

add_action('deactivated_plugin', fn($p) =>
    // Plugin deactivated
    wpauditor_log_event('PLUGIN_DEACTIVATED', "plugin=$p", ['category' => 'PLUGIN'])
);

add_action('switch_theme', fn($t) =>
    // Theme switched
    wpauditor_log_event('THEME_SWITCH', "theme=$t", ['category' => 'THEME'])
);

// Post hooks
add_action('save_post', function($id, $post, $upd) {
    // Post create/update
    $action = $upd ? 'POST_UPDATED' : 'POST_CREATED';
    wpauditor_log_event($action, "post_id=$id title={$post->post_title} type={$post->post_type}", ['category' => 'POST']);
}, 10, 3);

add_action('before_delete_post', function($id) {
    // Post deleted
    $post = get_post($id);
    if ($post) {
        wpauditor_log_event('POST_DELETED', "post_id=$id title={$post->post_title} type={$post->post_type}", ['category' => 'POST']);
    }
});
?>