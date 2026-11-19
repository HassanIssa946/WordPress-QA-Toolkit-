// No build step: plain wp.* globals. Dynamic block (saved as a comment; rendered by render.php).
( function ( blocks, element, blockEditor ) {
	blocks.registerBlockType( 'wpqa-fixture/notice', {
		edit: function ( props ) {
			return element.createElement( 'p', blockEditor.useBlockProps(), 'WPQA notice: ' + ( props.attributes.message || '(empty)' ) );
		},
		save: function () {
			return null;
		},
	} );
} )( window.wp.blocks, window.wp.element, window.wp.blockEditor );
