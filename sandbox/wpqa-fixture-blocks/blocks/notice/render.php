<?php
/**
 * @var array $attributes Block attributes.
 */
defined( 'ABSPATH' ) || exit;
printf(
	'<div %1$s data-level="%2$s" data-count="%3$d"%4$s>%5$s</div>',
	get_block_wrapper_attributes( array( 'class' => 'wpqa-notice' ) ),
	esc_attr( $attributes['level'] ?? 'info' ),
	(int) ( $attributes['count'] ?? 1 ),
	! empty( $attributes['dismissible'] ) ? ' data-dismissible="1"' : '',
	esc_html( $attributes['message'] ?? '' )
);
