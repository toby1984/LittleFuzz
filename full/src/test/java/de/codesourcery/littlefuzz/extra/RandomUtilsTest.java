package de.codesourcery.littlefuzz.extra;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RandomUtilsTest
{
    private RandomUtils randomUtils;

    @BeforeEach
    void setup() {
        randomUtils = new RandomUtils( new Random() );
    }

    enum MyEnum {
        A, B, C
    }

    @Test
    void testPickRandomEnumValue() {
        final Optional<Object> pick = randomUtils.pickRandomEnumValue( MyEnum.class );
        assertThat( pick ).isPresent();
        assertThat( pick.get() ).isInstanceOf( MyEnum.class );
    }

    @Test
    void testPickRandomCollectionValue() {

        final Set<Integer> set = Set.of( 1, 2, 3, 4, 5 );
        // test with repetition forbidden
        for ( int i = 0 ; i < 1000 ; i++ )
        {
            final List<Integer> picked = randomUtils.pickRandomElements( set, 3, false );
            assertThat( picked ).hasSize( 3 );
            assertThat( picked.stream().distinct().count() ).isEqualTo( 3 );
        }

        // test with repetition allowed
        boolean foundRepetition = false;
        for ( int i = 0 ; i < 10000 ; i++ )
        {
            final List<Integer> picked = randomUtils.pickRandomElements( set, 3, true );
            assertThat( picked ).hasSize( 3 );
            if ( picked.stream().distinct().count() < 3 ) {
                foundRepetition = true;
                break;
            }
        }
        assertThat( foundRepetition ).isTrue();

        // test edge cases
        assertThatThrownBy( () -> randomUtils.pickRandomElements( set, 10, false ) ).isInstanceOf( IllegalArgumentException.class );
        randomUtils.pickRandomElements( set, 10, true );
        assertThatThrownBy( () -> randomUtils.pickRandomElements( set, -1, false ) ).isInstanceOf( IllegalArgumentException.class );
        assertThatThrownBy( () -> randomUtils.pickRandomElements( set, 0, false ) ).isInstanceOf( IllegalArgumentException.class );
        assertThatThrownBy( () -> randomUtils.pickRandomElements( null, 5, false ) ).isInstanceOf( NullPointerException.class );
    }

    @Test
    void testCreateRandomStringEdgeCases() {

        final char[] candidates = "ABCDEF".toCharArray();
        final Set<String> set = new HashSet<>();
        for ( int i = 0 ; i < 1000 ; i++ )
        {
            final String s1 = randomUtils.createRandomString( 1, 1, candidates );
            assertThat( s1 ).isNotNull();
            assertThat( s1 ).hasSize( 1 );
            assertThat( ArrayUtils.contains( candidates, s1.charAt( 0 ) ) ).isTrue();
            set.add( s1 );
        }
        assertThat( set ).hasSizeGreaterThan( 1 );

        assertThatThrownBy( () -> randomUtils.createRandomString( 1, 0, candidates ) ).isInstanceOf( IllegalArgumentException.class );
        assertThatThrownBy( () -> randomUtils.createRandomString( 1, -1, candidates ) ).isInstanceOf( IllegalArgumentException.class );
        assertThatThrownBy( () -> randomUtils.createRandomString( -1, 1, candidates ) ).isInstanceOf( IllegalArgumentException.class );
    }

    @Test
    void testCreateRandomString() {
        final char[] candidates = "ABCDEF".toCharArray();
        for ( int i = 0 ; i < 1000 ; i++ )
        {
            final String s = randomUtils.createRandomString( 1, 10, candidates );
            assertThat( s ).isNotNull();
            assertThat( s ).isNotBlank();
            assertThat( s ).hasSizeBetween( 1, 10 );
            for ( final char c : s.toCharArray() )
            {
                assertThat( ArrayUtils.contains(candidates, c ) ).describedAs( "Unexpected character '"+c+"' in string ?" ).isTrue();
            }
        }
    }
}