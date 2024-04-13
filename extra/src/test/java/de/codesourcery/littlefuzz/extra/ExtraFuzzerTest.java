package de.codesourcery.littlefuzz.extra;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import de.codesourcery.littlefuzz.core.Fuzzer;
import de.codesourcery.littlefuzz.core.IFieldValueGenerator;
import de.codesourcery.littlefuzz.core.IFuzzingRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExtraFuzzerTest
{
    static class Superclass {
        Long a;
    }

    static class Subclass extends Superclass {

        static Long c;

        Long b;
    }

    class A {
        byte b;
        Byte B;

        short c;
        Short C;

        int a;
        Integer A;

        long d;
        Long D;

        float e;
        Float E;

        double f;
        Double F;

        String S;

        ZonedDateTime zonedDateTime;

        public A()
        {
        }

        public A(A other)
        {
            this.b = other.b;
            this.B = other.B;
            this.c = other.c;
            this.C = other.C;
            this.a = other.a;
            this.A = other.A;
            this.d = other.d;
            this.D = other.D;
            this.e = other.e;
            this.E = other.E;
            this.f = other.f;
            this.F = other.F;
            this.S = other.S;
            this.zonedDateTime = other.zonedDateTime;
        }
    }

    public enum EmptyEnum {
    }

    public enum NonEmptyEnum {
        A,B,C
    }

    private GeneratorHelpers generatorHelpers;
    private DifferentValueGenerator diffValues;
    private Fuzzer f;

    private IFieldValueGenerator differentValues(Supplier<?> s) {
        return diffValues.wrap( ctx -> s.get() );
    }

    private Function<Supplier<?>, IFieldValueGenerator> differentValues() {
        return supplier -> diffValues.wrap( ctx -> supplier.get() );
    }

    @BeforeEach
    public void setup() {
        diffValues = new DifferentValueGenerator( 10 );
        f = new Fuzzer();
        generatorHelpers = new GeneratorHelpers( new Random() );
        generatorHelpers.setupDefaultRules( f, differentValues() );
    }

    @Test
    public void testPickEnumValues()
    {
        for (int i = 0 ; i < 10 ; i++)
        {
            assertThat( generatorHelpers.pickRandomEnumValue( EmptyEnum.class ) ).isEmpty();
        }

        final Set<NonEmptyEnum> toTest = new HashSet<>();
        for (int i = 0 ; i < 10 ; i++)
        {
            final Optional<Object> v = generatorHelpers.pickRandomEnumValue( NonEmptyEnum.class );
            assertThat( v ).isPresent();
            toTest.add( (NonEmptyEnum) v.get() );
        }
        assertThat( toTest ).hasSizeGreaterThan( 1 );
    }

    static class FastTest {
        byte value;
    }

    @Test
    public void testDefaultRulesDoNotGenerateIdenticalValues() throws IllegalAccessException
    {
        final FastTest t = new FastTest();
        int retires = 10000;
        int sameValue = 0;
        int differentValue = 0;

        while ( retires-- > 0 ) {
            byte oldValue = t.value;
            f.assignRandomValues( t );
            if ( t.value == oldValue ) {
                sameValue++;
            } else {
                differentValue++;
            }
        }
        assertThat( sameValue ).isZero();
        assertThat( differentValue ).isNotZero();
    }

    @Test
    public void testDefaultRulesGenerateIdenticalValues() throws IllegalAccessException
    {
        f = new Fuzzer();
        generatorHelpers.setupDefaultRules( f, null );

        final FastTest t = new FastTest();
        int retires = 10000;
        int sameValue = 0;
        int differentValue = 0;

        while ( retires-- > 0 ) {
            byte oldValue = t.value;
            f.assignRandomValues( t );
            if ( t.value == oldValue ) {
                sameValue++;
            } else {
                differentValue++;
            }
        }
        assertThat( sameValue ).isNotZero();
        assertThat( differentValue ).isNotZero();
    }

    @Test
    public void testStringGeneration()
    {
        //
        for (int i = 0 ; i < 100 ; i++)
        {
            final String s = generatorHelpers.createRandomString( 0, 0 );
            assertThat( s ).isEmpty();
        }

        //
        for (int i = 0 ; i < 100 ; i++)
        {
            final String s = generatorHelpers.createRandomString( 10, 10 );
            assertThat( s ).hasSize( 10 );
        }

        //
        final Set<String> strings = new HashSet<>();
        for (int i = 0 ; i < 100 ; i++)
        {
            final String s = generatorHelpers.createRandomString( 0, 10 );
            strings.add( s );
            assertThat( s.length() ).isBetween( 0, 10 );
        }
        assertThat( strings.size() ).isGreaterThan( 1 );
    }

    @Test
    public void testAssignSimpleFields() throws IllegalAccessException
    {
        final A obj = f.assignRandomValues( new A() );
        assertNotNull( obj.A );
        assertNotNull( obj.B );
        assertNotNull( obj.C );
        assertNotNull( obj.D );
        assertNotNull( obj.E );
        assertNotNull( obj.F );
        assertNotNull( obj.S );

        // test repeated assignments
        final Set<String> values = new HashSet<>();
        for ( int i = 0 ; i < 10 ; i++)
        {
            A copy = new A( obj );
            values.add( ReflectionToStringBuilder.toString( obj ) );
            f.assignRandomValues( obj );
            assertThat( EqualsBuilder.reflectionEquals( copy, obj ) ).isFalse();
        }
        assertThat( values ).hasSizeGreaterThan( 1 );
    }

    @Test
    public void testGenerateRandomMap() {

        final Map<String, String> map =
            generatorHelpers.createRandomStringMap( 1, 5, 10, 20 );

        for ( final Map.Entry<String, String> entry : map.entrySet() )
        {
            assertThat( entry.getKey() ).hasSizeBetween( 1, 5 );
            assertThat( entry.getValue() ).hasSizeBetween( 10, 20 );
        }
        assertThat( map ).isNotEmpty();
    }

    @Test
    public void testPickRandomElementsWithList() {

        for ( int i = 0 ; i < 10 ; i++ ) {
            final List<String> l =
                generatorHelpers.pickRandomElements( List.of( "a", "b", "c", "d", "e", "f" ), 3, true );
            assertThat( l ).hasSize( 3 );
        }
    }

    @Test
    public void testPickRandomUniqueElementsWithList() {

        for ( int i = 0 ; i < 10 ; i++ ) {
            final List<String> l =
                generatorHelpers.pickRandomElements( List.of( "a", "b", "c", "d", "e", "f" ), 3, false );
            assertThat( l ).hasSize( 3 );
            assertThat( new HashSet<>(l) ).hasSize( l.size() );
        }
    }

    @Test
    public void testPickRandomElementsWithCollection() {

        for ( int i = 0 ; i < 10 ; i++ ) {
            final List<String> l =
                generatorHelpers.pickRandomElements( Set.of( "a", "b", "c", "d", "e", "f" ), 3, true );
            assertThat( l ).hasSize( 3 );
        }
    }

    @Test
    public void testPickRandomUniqueElementsWithCollection() {

        for ( int i = 0 ; i < 10 ; i++ ) {
            final List<String> l =
                generatorHelpers.pickRandomElements( Set.of( "a", "b", "c", "d", "e", "f" ), 3, false );
            assertThat( l ).hasSize( 3 );
            assertThat( new HashSet<>(l) ).hasSize( l.size() );
        }
    }

    static class Custom {
        long value;
    }

    @Test
    public void testBadGeneratorFunctionIsDetected() {

        final Custom obj = new Custom();
        obj.value = 42L;

        f.setTypeRule( IFuzzingRule.fromSupplier( differentValues( () -> 42L ) ) , Long.TYPE );

        assertThatThrownBy( () -> f.assignRandomValues( obj ) ).isInstanceOf( RuntimeException.class );
    }

    static class EqualityTest {
        Superclass value;
    }

    @Test
    void testUsesDefaultEqualityRuleIfNoSpecificOneConfigured() throws IllegalAccessException {

        f.addFieldRule( EqualityTest.class, "value", IFuzzingRule.fromSupplier( Subclass::new ) );
        final EqualityTest obj = new EqualityTest();
        obj.value = new Superclass();
        f.assignRandomValues( obj );
    }

    @Test
    void testRequiresCustomEqualityRule() {

        f.addFieldRule( EqualityTest.class, "value", IFuzzingRule.fromSupplier( differentValues( Subclass::new ) ) ) ;
        final BiPredicate<Object,Object> rule = EasyMock.createMock( BiPredicate.class);
        replay( rule );

        diffValues.addEqualityRule( Superclass.class, rule );
        final EqualityTest obj = new EqualityTest();
        obj.value = new Superclass();

        assertThatThrownBy( () -> f.assignRandomValues( obj ) ).isInstanceOf( RuntimeException.class );
        verify( rule );
    }

    @Test
    void testCustomEqualityRule() throws IllegalAccessException {

        f.addFieldRule( EqualityTest.class, "value", IFuzzingRule.fromSupplier( differentValues( Subclass::new ) ) );
        final BiPredicate<Object,Object> rule = EasyMock.createMock(BiPredicate.class);
        expect( rule.test( anyObject(), anyObject() ) ).andReturn( false );
        replay( rule );

        diffValues.addEqualityRule( Superclass.class, rule );
        diffValues.addEqualityRule( Subclass.class, rule );

        final EqualityTest obj = new EqualityTest();
        obj.value = new Superclass();

        f.assignRandomValues( obj );
        assertThat( obj.value ).isInstanceOf( Subclass.class );
        verify( rule );
    }
}