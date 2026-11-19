<?php
/**
 * Real-site pattern: block render template. WordPress includes it inside a function, so $post, $id and
 * $title are local variables, not the WordPress globals PHPCS warns about.
 *
 * @package SafeFixture
 */

defined( 'ABSPATH' ) || exit;

$post  = get_post( (int) ( $attributes['postId'] ?? 0 ) );
$title = $post ? get_the_title( $post ) : '';
$id    = wp_unique_id( 'sf-card-' );
?>
<div id="<?php echo esc_attr( $id ); ?>" <?php echo get_block_wrapper_attributes(); // phpcs:ignore WordPress.Security.EscapeOutput ?>>
	<?php echo esc_html( $title ); ?>
</div>
