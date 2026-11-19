<?php
/**
 * Real-site pattern: a Settings API form posting to options.php. settings_fields() prints the nonce.
 *
 * @package SafeFixture
 */

defined( 'ABSPATH' ) || exit;

function sf_settings_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<form method="post" action="options.php">
			<?php settings_fields( 'sf_settings' ); ?>
			<?php do_settings_sections( 'sf_settings' ); ?>
			<?php submit_button(); ?>
		</form>
	</div>
	<?php
}
