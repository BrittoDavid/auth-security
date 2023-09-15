package co.com.lucasian.auth.britto.cloud.repository;

/**
 *
 * @author DavidBritto
 */
import co.com.lucasian.auth.britto.cloud.entity.PartnerEntity;
import org.springframework.data.repository.CrudRepository;

import java.math.BigInteger;
import java.util.Optional;

public interface PartnerRepository extends CrudRepository<PartnerEntity, BigInteger> {

    Optional<PartnerEntity>findByClientId(String clientId);
}