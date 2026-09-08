<?php
/*
 * Template Name: RingEX Live Dashboard
 */

get_header(); 
?>

<main id="primary" class="site-main">
    <!-- max-width: 98% wie beim anderen Board für volle Breite ohne Scrollbalken -->
    <div class="container" style="max-width: 98%; padding: 0 20px; margin: 0 auto;"> 
        
        <?php
        $app_pfad = __DIR__ . '/ringex-app/dashboard_ex.php';
        
        if ( file_exists( $app_pfad ) ) {
            include( $app_pfad );
        } else {
            echo '<p>Dashboard-Datei nicht gefunden.</p>';
        }
        ?>

    </div>
</main>

<?php 
get_footer(); 
?>
