import unittest
from laurelin.extensions import posix


class TestPosixExtension(unittest.TestCase):
    def test__find_available_idnumber(self):
        """Test the _find_available_idnumber function"""

        min = 100
        expected = str(min)
        actual = posix._find_available_idnumber([], min, True)
        self.assertEqual(expected, actual, msg='Empty id_number list handling')

        actual = posix._find_available_idnumber([103], min, True)
        self.assertEqual(expected, actual, msg='Single id_number list entry with fill_gaps')

        expected = '104'
        actual = posix._find_available_idnumber([103], min, False)
        self.assertEqual(expected, actual, msg='Single id_number list entry without fill_gaps')

        with self.assertRaises(posix.LDAPPOSIXError, msg='Detect duplicate id numbers'):
            posix._find_available_idnumber([107, 105, 106, 105], min, False)

        expected = str(min)
        actual = posix._find_available_idnumber([105, 103, 104], min, True)
        self.assertEqual(expected, actual, msg='Detect that min is available')

        expected = '106'
        actual = posix._find_available_idnumber([105, 103, 104], min, False)
        self.assertEqual(expected, actual, msg='No fill_gaps on arbitrary sequence')

        expected = str(min+4)
        actual = posix._find_available_idnumber([min, min+3, min+1, min+2], min, True)
        self.assertEqual(expected, actual, msg='Ensure going off the end of the sequence increments the highest id')

        expected = str(min+2)
        actual = posix._find_available_idnumber([min, min+3, min+1], min, True)
        self.assertEqual(expected, actual, msg='Find gap')
