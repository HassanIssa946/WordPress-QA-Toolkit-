# WordPress fix playbook

Use these patterns when fixing findings. Always keep the project's prefix and text domain.

## Output escaping (XSS)
Escape late, at the point of output, matching the context:
```php
echo esc_html( $title );                       // text
echo '<a href="' . esc_url( $url ) . '" title="' . esc_attr( $label ) . '">';
echo wp_kses_post( $html_from_editor );         // trusted-ish HTML
printf( esc_html__( 'Results for %s', 'textdomain' ), esc_html( $term ) );
```
Request data: `$term = isset( $_GET['brand'] ) ? sanitize_text_field( wp_unslash( $_GET['brand'] ) ) : '';`

## SQL ($wpdb)
```php
$wpdb->get_results( $wpdb->prepare(
	"SELECT ID FROM {$wpdb->posts} WHERE post_type = %s AND post_title LIKE %s",
	'brand', '%' . $wpdb->esc_like( $term ) . '%'
) );
```
Use `%d` for integers, `%s` for strings, `%i` for identifiers (WP 6.2+). Prefer WP_Query / get_posts when possible.

## REST routes
```php
register_rest_route( 'prefix/v1', '/partner', array(
	'methods'             => WP_REST_Server::CREATABLE,
	'callback'            => 'prefix_save_partner',
	'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
	'args'                => array(
		'name' => array( 'required' => true, 'sanitize_callback' => 'sanitize_text_field' ),
	),
) );
```
Public form endpoints (e.g. "Partner with us"): keep `__return_true` only with strict `args` validation,
a nonce (`X-WP-Nonce` from `wp_create_nonce( 'wp_rest' )`), rate limiting and spam protection.

## AJAX / admin-post (CSRF + authorization)
```php
// page: wp_localize_script( 'prefix-main', 'prefixAjax', array( 'nonce' => wp_create_nonce( 'prefix_contact' ) ) );
function prefix_handle_contact() {
	check_ajax_referer( 'prefix_contact', 'nonce' );
	// logged-in actions also need: if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( null, 403 );
	$msg = isset( $_POST['msg'] ) ? sanitize_textarea_field( wp_unslash( $_POST['msg'] ) ) : '';
	wp_send_json_success();
}
```
Forms: `wp_nonce_field( 'prefix_save', 'prefix_nonce' );` and `check_admin_referer( 'prefix_save', 'prefix_nonce' );`

## File paths / includes
Never include or read a path built from input. Map allowed values: `$tpls = array( 'a' => 'parts/a.php' ); locate_template( $tpls[ $key ] ?? 'parts/default.php', true );`

## Secrets
Move to wp-config.php (`define( 'PREFIX_STRIPE_KEY', getenv( 'STRIPE_KEY' ) );`), rotate the exposed key, remove it from git history (ask the user before rewriting history).

## Theme integration
- `wp_head()` before `</head>`, `wp_body_open()` after `<body>`, `wp_footer()` before `</body>`.
- `add_theme_support( 'title-tag' )` and remove hard-coded `<title>`.
- Enqueue assets in functions.php with versions: `wp_enqueue_style( 'prefix-style', get_stylesheet_uri(), array(), wp_get_theme()->get( 'Version' ) );`

## Blocks
- `block.json`: `"apiVersion": 3`, `"name": "namespace/block"`, `"textdomain"`, `file:` references that exist in the registered folder.
- Register from the build folder: `register_block_type( __DIR__ . '/build/brand-card' );` and run `npm run build`.

## Hardening (ask before changing wp-config/server)
- `define( 'DISALLOW_FILE_EDIT', true );`
- Live: `WP_DEBUG` false or `WP_DEBUG_DISPLAY` false + log outside web root.
- Headers (server or plugin): HSTS, X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff, Referrer-Policy.
- Email DNS: one SPF record, DMARC starting at `p=none`, then `quarantine`.
