<?php

namespace Admidio\Tests\Unit;

use Admidio\Infrastructure\Utils\FileSystemUtils;
use Admidio\Tests\Support\AdmidioTestCase;

class FileSystemUtilsTest extends AdmidioTestCase
{
    /**
     * @dataProvider svgFilenames
     */
    public function testSvgUploadsAreNotAllowed(string $filename): void
    {
        $this->assertFalse(FileSystemUtils::allowedFileExtension($filename));
    }

    public static function svgFilenames(): array
    {
        return array(
            array('drawing.svg'),
            array('drawing.SVG'),
            array('drawing.SvG'),
            array('drawing.svgz'),
            array('drawing.SVGZ'),
            array('drawing.png.svg')
        );
    }

    public function testOtherSupportedUploadsRemainAllowed(): void
    {
        foreach (array('photo.jpg', 'photo.PNG', 'photo.webp', 'document.pdf', 'document.docx', 'data.csv', 'archive.zip') as $filename) {
            $this->assertTrue(FileSystemUtils::allowedFileExtension($filename), $filename);
        }
    }

    /**
     * @dataProvider blockedExtensions
     */
    public function testBlockedExtensionsAreRejected(string $extension): void
    {
        foreach (array($extension, strtoupper($extension)) as $variant) {
            $filename = 'upload.' . $variant;
            $this->assertTrue(FileSystemUtils::isBlockedFileExtension($filename));
            $this->assertFalse(FileSystemUtils::allowedFileExtension($filename));
        }
    }

    public static function blockedExtensions(): array
    {
        return array_map(static fn(string $extension): array => array($extension), array(
            'php', 'php3', 'php4', 'php5', 'pht', 'html', 'htm', 'phtml', 'shtml',
            'htaccess', 'htpasswd', 'pl', 'js', 'vbs', 'asp', 'asa', 'cer', 'asax',
            'swf', 'xap', 'cgi', 'ssi', 'phar', 'svg', 'svgz'
        ));
    }

    public function testSvgIsNoLongerInTheSupportedFileFormats(): void
    {
        $this->assertSame('application/octet-stream', FileSystemUtils::getFileMimeType('drawing.svg'));
        $this->assertSame('bi-file-earmark-fill', FileSystemUtils::getFileIcon('drawing.svg'));
        $this->assertFalse(FileSystemUtils::isViewableFileInBrowser('drawing.svg'));
    }

    /**
     * Regression test for file names with umlauts that browsers saved as "angezÃ¼ndet": the real name
     * has to be sent as filename* in UTF-8, because a plain filename is only defined for ASCII.
     *
     * @dataProvider contentDispositionNames
     */
    public function testContentDispositionCarriesNonAsciiNamesAsUtf8(string $filename, string $expectedFallback, string $expectedEncoded): void
    {
        $this->assertSame(
            'attachment; filename="' . $expectedFallback . '"; filename*=UTF-8\'\'' . $expectedEncoded,
            FileSystemUtils::getContentDisposition('attachment', $filename)
        );
    }

    public static function contentDispositionNames(): array
    {
        return array(
            'ascii name' => array('report.pdf', 'report.pdf', 'report.pdf'),
            'umlauts' => array('Sind die Lichter angezündet.pdf', 'Sind die Lichter angezuendet.pdf', 'Sind%20die%20Lichter%20angez%C3%BCndet.pdf'),
            'capital umlauts and sharp s' => array('ÄÖÜ-Straße.txt', 'AeOeUe-Strasse.txt', '%C3%84%C3%96%C3%9C-Stra%C3%9Fe.txt'),
            'other non-ascii' => array('café 日本.pdf', 'caf_ __.pdf', 'caf%C3%A9%20%E6%97%A5%E6%9C%AC.pdf'),
            'quote, backslash, percent' => array('a"b\\c%d.txt', 'a_b_c_d.txt', 'a%22b%5Cc%25d.txt'),
            'invalid utf-8' => array("a\xE4b.pdf", 'a_b.pdf', 'a%E4b.pdf'),
            'ampersand and apostrophe stay literal' => array("Tom & Jerry's.txt", "Tom & Jerry's.txt", 'Tom%20%26%20Jerry%27s.txt')
        );
    }

    public function testContentDispositionKeepsTheDispositionType(): void
    {
        $this->assertStringStartsWith('inline; filename="', FileSystemUtils::getContentDisposition('inline', 'ü.pdf'));
    }

    public function testContentDispositionCannotBeUsedToInjectHeaders(): void
    {
        $header = FileSystemUtils::getContentDisposition('attachment', "a\r\nSet-Cookie: x=1.pdf");

        $this->assertStringNotContainsString("\r", $header);
        $this->assertStringNotContainsString("\n", $header);
    }
}
