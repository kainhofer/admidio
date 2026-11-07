<?php

namespace Admidio\Tests\Unit\Documents;

use Admidio\Documents\Entity\File;
use Admidio\Documents\Service\DocumentsService;
use Admidio\Tests\Support\AdmidioTestCase;

class DocumentsDownloadTest extends AdmidioTestCase
{
    /**
     * Exercise the download method with the real MIME type and viewability lookup.
     * Only database access and header emission are replaced.
     *
     * @dataProvider downloadTypes
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testDownloadHeaders(string $filename, bool $inline, string $disposition, string $mimeType, string $contentDisposition): void
    {
        require __DIR__ . '/Support/download-headers.php';
        $GLOBALS['documentDownloadHeaders'] = array();

        $contents = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>';
        $path = tempnam(sys_get_temp_dir(), 'admidio-download-');

        try {
            file_put_contents($path, $contents);

            $file = $this->getMockBuilder(File::class)
                ->disableOriginalConstructor()
                ->onlyMethods(array('getFullFilePath', 'getValue'))
                ->getMock();
            $file->method('getFullFilePath')->willReturn($path);
            // downloadFile() reads the name unencoded ('database'), isViewableInBrowser() with the default format
            $file->method('getValue')->willReturnCallback(
                static fn(string $column, string $format = '') => $column === 'fil_name' ? $filename : null
            );

            $service = $this->getMockBuilder(DocumentsService::class)
                ->disableOriginalConstructor()
                ->onlyMethods(array('prepareFileDownload'))
                ->getMock();
            $service->expects($this->once())->method('prepareFileDownload')->with('file-uuid')->willReturn($file);

            ob_start();
            try {
                $service->downloadFile('file-uuid', $inline);
                $body = ob_get_contents();
            } finally {
                ob_end_clean();
            }

            $headers = $GLOBALS['documentDownloadHeaders'];
            $this->assertContains('Content-Disposition: ' . $contentDisposition, $headers);
            $this->assertStringStartsWith($disposition . ';', $contentDisposition);
            $this->assertContains('Content-Type: ' . $mimeType, $headers);
            $this->assertContains('X-Content-Type-Options: nosniff', $headers);
            $this->assertContains('Content-Length: ' . strlen($contents), $headers);
            $this->assertSame($contents, $body);
        } finally {
            unlink($path);
        }
    }

    public static function downloadTypes(): array
    {
        $header = static fn(string $disposition, string $name): string
            => $disposition . '; filename="' . $name . '"; filename*=UTF-8\'\'' . $name;

        return array(
            // SVG uploads are blocked. Existing files must still be served as generic attachments.
            'existing SVG view request' => array('payload.svg', true, 'attachment', 'application/octet-stream', $header('attachment', 'payload.svg')),
            'existing uppercase SVG view request' => array('payload.SVG', true, 'attachment', 'application/octet-stream', $header('attachment', 'payload.SVG')),
            'existing SVG download' => array('payload.svg', false, 'attachment', 'application/octet-stream', $header('attachment', 'payload.svg')),
            'PNG preview' => array('image.png', true, 'inline', 'image/png', $header('inline', 'image.png')),
            'PNG download' => array('image.png', false, 'attachment', 'image/png', $header('attachment', 'image.png')),
            'PDF preview' => array('document.pdf', true, 'inline', 'application/pdf', $header('inline', 'document.pdf')),
            'text preview with active markup' => array('document.txt', true, 'inline', 'text/plain', $header('inline', 'document.txt')),
            'archive view request' => array('archive.zip', true, 'attachment', 'application/zip', $header('attachment', 'archive.zip')),
            'unknown file type' => array('document.unknown', true, 'attachment', 'application/octet-stream', $header('attachment', 'document.unknown')),
            // Regression: raw UTF-8 in filename="..." was saved by browsers as "angezÃ¼ndet.pdf".
            'umlauts in the file name' => array(
                'Sind die Lichter angezündet.pdf', false, 'attachment', 'application/pdf',
                'attachment; filename="Sind die Lichter angezuendet.pdf"; filename*=UTF-8\'\'Sind%20die%20Lichter%20angez%C3%BCndet.pdf'
            ),
            'quotes and ampersand are not HTML-encoded' => array(
                'Tom & "Jerry".pdf', true, 'inline', 'application/pdf',
                'inline; filename="Tom & _Jerry_.pdf"; filename*=UTF-8\'\'Tom%20%26%20%22Jerry%22.pdf'
            )
        );
    }
}
